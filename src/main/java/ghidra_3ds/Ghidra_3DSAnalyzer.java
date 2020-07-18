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
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;

import resources.ResourceManager;
import org.xml.sax.*;


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
	
	public Ghidra_3DSAnalyzer() throws IOException, SAXException {
		super("3DS IPC Analyser", "", AnalyzerType.INSTRUCTION_ANALYZER);
		this.setSupportsOneTimeAnalysis();
		
		svc_info = new HashMap<Integer, SVCInfo>();
		
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
			
			// err:f
			// srv:
			
			/*DecompInterface decompiler = new DecompInterface();
			
			Set<Function> port_functions = svc_connect_to_port.getCallingFunctions(monitor);
			for(Function f: port_functions) {
				DecompileResults r = decompiler.decompileFunction(f, 2, monitor);
				if(r.decompileCompleted()) {
					DecompiledFunction d = r.getDecompiledFunction();
					HighFunction hf =r.getHighFunction();
					//hf.
				}
			}*/
			
			Set<Function> potential_wrappers = svc_send_sync.getCallingFunctions(monitor);
			int i = 1;
			for(Function f: potential_wrappers) {
				try {
					f.setName("potentialIPCWrapper" + Integer.toString(i++), SourceType.ANALYSIS);
				} catch (DuplicateNameException | InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		return true;
	}
}
