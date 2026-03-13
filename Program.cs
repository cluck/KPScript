/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2025 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Windows.Forms;

using KeePass.App;
using KeePass.Forms;
using KeePass.UI;
using KeePass.Util;

using KeePassLib;
using KeePassLib.Cryptography;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Utility;

using KPScript.ScriptingModules;

namespace KPScript
{
	public static class Program
	{
		private const int ReturnCodeSuccess = 0;
		private const int ReturnCodeError = 1;

		private const string ScriptFileSuffix = "kps";

		private const string ParamCommand = "c";

		private const string CmdDetachBins = "detachbins";

		private const string KpsCopyright = @"Copyright © 2007-2025 Dominik Reichl";

		[STAThread]
		public static int Main(string[] args)
		{
			if((args == null) || (args.Length == 0))
			{
				PrintUsage();
				return ReturnCodeSuccess;
			}

			try
			{
				DpiUtil.ConfigureProcess();
				Application.EnableVisualStyles();
				Application.SetCompatibleTextRenderingDefault(false);
				Application.DoEvents(); // Required
			}
			catch(Exception) { Debug.Assert(false); }

			try
			{
				KeePass.Program.CommonInitialize();

				CommandLineArgs cmdArgs = new CommandLineArgs(args);
				string strFile = cmdArgs.FileName;

				if((strFile != null) && strFile.EndsWith(ScriptFileSuffix,
					StrUtil.CaseIgnoreCmp))
					KpsRunner.RunScriptFile(strFile);
				else RunScriptLine(cmdArgs);

				WriteLineColored("OK: " + KSRes.OperationSuccessful, ConsoleColor.Green);
				return ReturnCodeSuccess;
			}
			catch(Exception ex) { PrintException(ex); }
			finally
			{
				try { KeePass.Program.CommonTerminate(); }
				catch(Exception) { Debug.Assert(false); }
			}

			return ReturnCodeError;
		}

		private static void PrintUsage()
		{
			Console.WriteLine("KPScript - Scripting Plugin");
			Console.WriteLine(KpsCopyright);
			Console.WriteLine();
			Console.WriteLine(PwDefs.ShortProductName + " Runtime: " +
				PwDefs.VersionString);
		}

		private static void PrintException(Exception ex)
		{
			if(ex == null) { Debug.Assert(false); return; }

			string str = ex.Message;
			if(string.IsNullOrEmpty(str)) { Debug.Assert(false); str = KSRes.UnknownException; }

			WriteLineColored("E: " + str, ConsoleColor.Red);
		}

		internal static void WriteLineColored(string strText, ConsoleColor clr)
		{
			ConsoleColor clrPrevFg = Console.ForegroundColor;
			ConsoleColor clrPrevBg = Console.BackgroundColor;
			
			if(clr != clrPrevFg) Console.ForegroundColor = clr;
			if(clrPrevBg == clr)
			{
				if(clrPrevBg == ConsoleColor.Black)
					Console.BackgroundColor = ConsoleColor.Gray;
				else Console.BackgroundColor = ConsoleColor.Black;
			}

			Console.WriteLine(strText);

			Console.BackgroundColor = clrPrevBg;
			Console.ForegroundColor = clrPrevFg;
		}

		private static void RunScriptLine(CommandLineArgs args)
		{
			string strCommand = args[ParamCommand];
			if(string.IsNullOrEmpty(strCommand))
				throw new InvalidOperationException(KSRes.NoCommand);
			strCommand = strCommand.ToLowerInvariant();

			if(string.IsNullOrEmpty(args.FileName))
			{
				RunSingleCommand(strCommand, args);
				return;
			}

			IOConnectionInfo ioc = new IOConnectionInfo();
			ioc.Path = args.FileName;
			ioc.CredSaveMode = IOCredSaveMode.NoSave;

			CompositeKey cmpKey = KpsUtil.GetMasterKey(args, null, ioc);
			if((cmpKey == null) || (cmpKey.UserKeyCount == 0)) return;

			PwDatabase pwDb = new PwDatabase();

			if(strCommand == CmdDetachBins)
			{
				string strDir = UrlUtil.GetFileDirectory(ioc.Path, false, true);
				pwDb.DetachBinaries = strDir;

				pwDb.Open(ioc, cmpKey, null);
				pwDb.Save(null);
			}
			else
			{
				pwDb.Open(ioc, cmpKey, null);

				bool bNeedsSave;
				RunFileCommand(strCommand, args, pwDb, out bNeedsSave);

				if(bNeedsSave) pwDb.Save(null);
			}

			pwDb.Close();
		}

		private static void RunSingleCommand(string strCommand, CommandLineArgs args)
		{
			if(FnMod.ProcessCommand(strCommand, args))
				return;

			throw new Exception(KSRes.UnknownCommand);
		}

		private static void RunFileCommand(string strCommand, CommandLineArgs args,
			PwDatabase pwDb, out bool bNeedsSave)
		{
			bNeedsSave = false;

			if(ReportingMod.ProcessCommand(strCommand, args, pwDb, out bNeedsSave))
				return;
			if(EntryMod.ProcessCommand(strCommand, args, pwDb, out bNeedsSave))
				return;
			if(DataExchangeMod.ProcessCommand(strCommand, args, pwDb, out bNeedsSave))
				return;
			if(DatabaseMod.ProcessCommand(strCommand, args, pwDb, out bNeedsSave))
				return;

			throw new Exception(KSRes.UnknownCommand);
		}
	}
}
