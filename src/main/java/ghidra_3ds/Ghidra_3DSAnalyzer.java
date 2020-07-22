/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_3ds;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.MemReferenceImpl;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.ProgramContextImpl;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import resources.ResourceManager;
import org.xml.sax.*;

class FuncArgs {
	long r0;
	long r1;

	public FuncArgs(long a, long b) {
		r0 = a;
		r1 = b;
	}
}

class MyErrorHandler implements ErrorHandler {
	private MessageLog log;

	MyErrorHandler(MessageLog log) {
		this.log = log;
	}

	/**
	 * @see org.xml.sax.ErrorHandler#error(org.xml.sax.SAXParseException)
	 */
	@Override
	public void error(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
	}

	/**
	 * @see org.xml.sax.ErrorHandler#fatalError(org.xml.sax.SAXParseException)
	 */
	@Override
	public void fatalError(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
	}

	/**
	 * @see org.xml.sax.ErrorHandler#warning(org.xml.sax.SAXParseException)
	 */
	@Override
	public void warning(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
	}
}

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class Ghidra_3DSAnalyzer extends AbstractAnalyzer {

	Map<Integer, SVCInfo> svc_info;
	Map<String, Map<Long, String>> ipc_function_info;

	public Ghidra_3DSAnalyzer() throws IOException, SAXException {
		super("3DS IPC Analyser", "", AnalyzerType.INSTRUCTION_ANALYZER);
		this.setSupportsOneTimeAnalysis();
		
		svc_info = new HashMap<Integer, SVCInfo>();
		ipc_function_info = new HashMap<>();
		
		File svc_definitions = ResourceManager.getResourceFile("svcs.xml");
		if(svc_definitions != null) {
			SVCInfo current_svc = null;
			int current_svc_number = 0;

			XmlPullParser parser = XmlPullParserFactory.create(svc_definitions, new MyErrorHandler(new MessageLog()), false);
			while (parser.hasNext()) {
				XmlElement element = parser.next();
				
				String name = element.getName();

				if(name.equals("svc")) {
					if(element.isStart()) {
						current_svc = new SVCInfo();
						current_svc_number = Integer.decode(element.getAttribute("number"));
					}
					else if(element.isEnd()) {
						svc_info.put(current_svc_number, current_svc);
					}
				}
				else if(element.getName().equals("name")) {
					current_svc.name = element.getText();
				}
				else if(element.getName().equals("attributes")) {
					current_svc.attributes = element.getText();
				}
			}
		}
		
		File service_definitions = ResourceManager.getResourceFile("functions.xml");
		if(service_definitions != null) {
			String current_func_name = null;
			long current_func_id = 0;
			String current_port = null;

			XmlPullParser parser = XmlPullParserFactory.create(service_definitions, new MyErrorHandler(new MessageLog()), false);
			while (parser.hasNext()) {
				XmlElement element = parser.next();
				
				String name = element.getName();

				if(name.equals("port")) {
					if(element.isStart()) {
						current_port = element.getAttribute("name");
						ipc_function_info.put(current_port, new HashMap<>());
					}
				}
				else if(name.equals("function")) {
					if(element.isStart()) {
					}
					else if(element.isEnd()) {
						ipc_function_info.get(current_port).put(current_func_id, current_func_name);
					}
				}
				else if(element.getName().equals("name")) {
					current_func_name = element.getText();
				}
				else if(element.getName().equals("ipc_id") && element.isEnd()) {
					try {
					current_func_id = Long.parseLong(element.getText());
					}
					catch(Exception e) {
						System.out.println(e);
					}
				}
			}
		}
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getExecutableFormat().equals("Nintendo 3DS Binary (CXI)");
	}

	@Override
	public void registerOptions(Options options, Program program) {
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		DataTypeManager dtm = program.getDataTypeManager();
		
		CParser svc_parser = new CParser(dtm, true, null);
		File svc_header = ResourceManager.getResourceFile("svc.h");
		FileInputStream svc_fis = null;
		try {
			svc_fis = new FileInputStream(svc_header);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			svc_parser.parse(svc_fis);
		} catch (ParseException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		InstructionIterator iter = program.getListing().getInstructions(true);
		
		// for tracking later
		Function svc_send_sync = null; 
		Function svc_connect_to_port = null;
		
		// for storage override
		Function svc_get_system_tick = null; 
		
		while (iter.hasNext()) {
			Instruction instruction = iter.next();
			if(instruction.getMnemonicString().equals("swi")) {
				Scalar svc_number_scalar = (Scalar)instruction.getOpObjects(0)[0];
				int svc_number = (int)svc_number_scalar.getUnsignedValue();

				Function f = program.getListing().getFunctionContaining(instruction.getAddress());

				if(svc_number == 0x28) {
					svc_get_system_tick = f;
				}
				if(svc_number == 0x2d) {
					svc_connect_to_port = f;
				}
				if(svc_number == 0x32) {
					svc_send_sync = f;
				}

				try {
					SVCInfo info = svc_info.get(svc_number);
					f.setName(info.name, SourceType.ANALYSIS);
					if(info.attributes != null && info.attributes.equals("noreturn")) {
						f.setNoReturn(true);
					}
					
					// TODO: fiddle with the pcode to make the svc a call override
					
				} catch (DuplicateNameException | InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		List<DataTypeManager> dtms = new ArrayList<DataTypeManager>();
		dtms.add(dtm);

		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(dtms, set, SourceType.ANALYSIS, true, false);
		cmd.applyTo(program);

		if(svc_get_system_tick != null) {
			//svc_get_system_tick.setCustomVariableStorage(true);
			DataType u64 = dtm.getDataType("/u64");
			ProgramContext ctx = program.getProgramContext();
			try {
				VariableStorage vs = new VariableStorage(program, ctx.getRegister("r0"), ctx.getRegister("r1"));
				ReturnParameterImpl returnValue = new ReturnParameterImpl(u64, vs, program);
				svc_get_system_tick.updateFunction(null, returnValue, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS, new Parameter[0]);
			} catch (DuplicateNameException | InvalidInputException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		if(svc_connect_to_port != null && svc_send_sync != null) {
			Set<Function> port_functions = svc_connect_to_port.getCallingFunctions(monitor);
			for(Function f: port_functions) {
				Set<Address> call_sites = getCallSites(program, f, svc_connect_to_port, monitor);
				// resolveconstants todo
				// workaround "Don't trust zero values loaded out of memory, even if it is read-only memory"
				Map<Address, FuncArgs> vals = resolveConstants(f, call_sites, program, monitor);
				
				for(FuncArgs p: vals.values()) {
					//System.out.println(p.r0);
					//System.out.println(p.r1);
					
					MemoryByteProvider mem_bytes = new MemoryByteProvider(program.getMemory(), program.getAddressFactory().getDefaultAddressSpace());
					BinaryReader br = new BinaryReader(mem_bytes, true);
					
					// todo: read port name
					try {
						f.setName("connectToPort_" + br.readAsciiString(p.r1), SourceType.ANALYSIS);
					} catch (DuplicateNameException | InvalidInputException | IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
			
			Symbol srv_port_handle = program.getSymbolTable().getGlobalSymbols("srv_port_handle").get(0);
			Set<Function> srv_ipc_functions = labelIpc(program, monitor, port_functions, "srv", ipc_function_info.get("srv"), srv_port_handle);
			
			// ok, we found srv symbols! yay!
			
			Symbol get_service_handle_symbol = program.getSymbolTable().getGlobalSymbols("srvGetServiceHandle").get(0);
			Function get_service_handle = program.getFunctionManager().getFunctionContaining(get_service_handle_symbol.getAddress());
			
			Map<Address, String> service_handles = new HashMap<>();
			
			Set<Function> service_handle_getters = get_service_handle.getCallingFunctions(monitor);
			for(Function f: service_handle_getters) {
				Set<Address> call_sites = getCallSites(program, f, get_service_handle, monitor);
				// resolveconstants todo
				// workaround "Don't trust zero values loaded out of memory, even if it is read-only memory"
				Map<Address, FuncArgs> vals = resolveConstants(f, call_sites, program, monitor);
				
				for(FuncArgs p: vals.values()) {
					MemoryByteProvider mem_bytes = new MemoryByteProvider(program.getMemory(), program.getAddressFactory().getDefaultAddressSpace());
					BinaryReader br = new BinaryReader(mem_bytes, true);

					try {
						String service_name = br.readAsciiString(p.r1);
						Address service_handle = program.getAddressFactory().getDefaultAddressSpace().getAddress(p.r0);
						Symbol symbol = program.getSymbolTable().getSymbols(service_handle)[0];
						symbol.setName(service_name + "_session_handle", SourceType.ANALYSIS);
						
						f.setName("get_service_handle_" + service_name, SourceType.ANALYSIS);
					} catch (DuplicateNameException | InvalidInputException | IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
			
			SymbolIterator it = program.getSymbolTable().getSymbolIterator();
			for(Symbol sym: it) {
				String name = sym.getName();
				if(name.endsWith("_session_handle")) {
					String port_name = name.substring(0, name.length()-15);

					if(ipc_function_info.containsKey(port_name)) {
						labelIpc(program, monitor, new HashSet<>(), port_name, ipc_function_info.get(port_name), sym);
					} 
					else {
						System.out.println("Totally missing " +port_name);
						labelIpc(program, monitor, new HashSet<>(), port_name, new HashMap<>(), sym);
					}
				}
			}
			
			/*Set<Function> potential_wrappers = svc_send_sync.getCallingFunctions(monitor);
			int i = 1;
			for(Function f: potential_wrappers) {
				if(srv_ipc_functions.contains(f)) continue;

				try {
					f.setName("unknownIPCWrapper" + Integer.toString(i++), SourceType.ANALYSIS);
				} catch (DuplicateNameException | InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}*/
		}
		return true;
	}
	
	Set<Function> labelIpc(Program program, TaskMonitor monitor, Set<Function> port_functions, String service_name, Map<Long, String> id_mapping, Symbol handle_symbol) {		
		//Symbol handle_symbol = program.getSymbolTable().getGlobalSymbols(handle_name).get(0);
		Address handle_address = handle_symbol.getAddress();
		
		Set<Function> ipc_functions = new HashSet<Function>();
		ReferenceIterator ri = program.getReferenceManager().getReferencesTo(handle_address);
		for(Reference ref: ri) {
			Address from = ref.getFromAddress();
			Function from_func = program.getFunctionManager().getFunctionContaining(from);
			if(from_func != null && !port_functions.contains(from_func)) 
				ipc_functions.add(from_func);
		}
		
		int i = 1;
		for(Function f: ipc_functions) {
			try {
				long id = determineIpcId(program, monitor, f);
				if(id_mapping.containsKey(id)) {
					f.setName(id_mapping.get(id), SourceType.ANALYSIS);
				} else {
					f.setName(service_name + "IPCWrapper" + Integer.toString(i++), SourceType.ANALYSIS);
				}
			} catch (DuplicateNameException | InvalidInputException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		return ipc_functions;
	}
	
	// TODO: this sucks major ass, gut it and replace with emulation
	long determineIpcId(Program program, TaskMonitor monitor, Function func) {
		//System.out.println(func.getName());
		
 		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(program);
		DecompileResults results = decomp.decompileFunction(func, 0, monitor);

		if(results.decompileCompleted()) {
			HighFunction hf = results.getHighFunction();
			ArrayList<PcodeBlockBasic> blocks = hf.getBasicBlocks();
			Iterator<PcodeOpAST> pcode_ops = hf.getPcodeOps();
			
			Varnode tls = null;
			
			while(pcode_ops.hasNext()) {
				PcodeOpAST pcode_op = pcode_ops.next();
				// track callothers
				
				//System.out.println(pcode_op.toString());
				
				if(pcode_op.getOpcode() == PcodeOp.CALLOTHER) {
					int index = (int) pcode_op.getInput(0).getOffset();
					if (program.getLanguage().getUserDefinedOpName(index).equals("coproc_movefrom_User_R_Thread_and_Process_ID")) {
						// tls located
						tls = pcode_op.getOutput();
						//System.out.println("Found TLS:" + tls.toString());
					}
				}
				else if(pcode_op.getOpcode() == PcodeOp.CALL) {
					// track calls to svc_whatever
				}
				else if(pcode_op.getOpcode() == PcodeOp.STORE) {
					Varnode[] inputs = pcode_op.getInputs();
					
					if(tls != null && inputs[1].getAddress().equals(tls.getAddress())) {
						//System.out.print("yeet tls ");
						
						if(inputs[2].isConstant()) {
							long constant_data = inputs[2].getOffset();
							//System.out.println("constant " + Long.toString(constant_data, 16));
							return constant_data;
						}
						// else
						//System.out.println("data:" + inputs[2].toString());
						if(inputs[2].getAddress().isMemoryAddress()) {
							byte[] dest = new byte[4];
							try {
								program.getMemory().getBytes(inputs[2].getAddress(), dest);
								ByteArrayProvider provider = new ByteArrayProvider(dest);
								BinaryReader r = new BinaryReader(provider, true);
								return r.readUnsignedInt(0);
							} catch (MemoryAccessException | IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
					}
				}
			}
		}

		return 0;
	}
	
	private Set<Address> getCallSites(Program program, Function target_func, Function called_func, TaskMonitor tMonitor) throws CancelledException {
		Set<Address> call_sites = new HashSet<>();
		
		tMonitor.checkCanceled();
		for (Instruction inst : program.getListing().getInstructions(target_func.getBody(), true)) {
			if (inst.getMnemonicString().equals("bl")) {
				if((inst.getOperandType(0) & OperandType.ADDRESS) == OperandType.ADDRESS) {
					Address call_addr = (Address)inst.getOpObjects(0)[0];
					if(call_addr.getOffset() == called_func.getEntryPoint().getOffset()) {
						call_sites.add(inst.getAddress());
					}
				}
			}
		}
		return call_sites;
	}
	
	private Map<Address, FuncArgs> resolveConstants(Function func, Set<Address> call_sites,
			Program program, TaskMonitor tMonitor) throws CancelledException {
		Map<Address, FuncArgs> values = new HashMap<>();
		
		ProgramContext ctx = program.getProgramContext();
		
		Register r0 = ctx.getRegister("r0");
		Register r1 = ctx.getRegister("r1");
		
		Address start = func.getEntryPoint();
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(true);
		SymbolicPropogator sym_eval = new SymbolicPropogator(program);

		sym_eval.flowConstants(start, func.getBody(), eval, true, tMonitor);
		for (Address call_site : call_sites) {
			Value val_r0 = sym_eval.getRegisterValue(call_site, r0);
			Value val_r1 = sym_eval.getRegisterValue(call_site, r1);
			if (val_r0 == null) {
				System.out.println(call_site.toString() + " - couldn't resolve value of " + r0);
				continue;
			}
			if (val_r1 == null) {
				System.out.println(call_site.toString() + " - couldn't resolve value of " + r1);
				continue;
			}
			values.put(call_site, new FuncArgs(val_r0.getValue(), val_r1.getValue()));
		}
		return values;
	}
}
