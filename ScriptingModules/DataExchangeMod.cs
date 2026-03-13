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
using System.Text;
using System.IO;

using KeePass.DataExchange;
using KeePass.Util;

using KeePassLib;
using KeePassLib.Delegates;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KPScript.ScriptingModules
{
	public sealed class PwDatabaseSaver : IUIOperations
	{
		private PwDatabase m_db;

		public PwDatabaseSaver(PwDatabase pwDb)
		{
			m_db = pwDb;
		}

		public bool UIFileSave(bool bForceSave)
		{
			if(m_db == null) return true;

			try { m_db.Save(null); }
			catch(Exception) { return false; }

			return true;
		}
	}

	public static class DataExchangeMod
	{
		private const string CmdImport = "import";
		private const string CmdExport = "export";
		private const string CmdSync = "sync";

		private const string ParamXslFile = "XslFile"; // See XslTransform2x
		private const string ParamXslFileCL = "xslfile";

		public static bool ProcessCommand(string strCommand, CommandLineArgs args,
			PwDatabase pwDatabase, out bool bNeedsSave)
		{
			bNeedsSave = false;

			if(strCommand == CmdImport)
				bNeedsSave = PerformImport(pwDatabase, args);
			else if(strCommand == CmdExport)
				PerformExport(pwDatabase, args);
			else if(strCommand == CmdSync)
				PerformSync(pwDatabase, args); // No save on sync
			else return false;

			return true;
		}

		private static FileFormatProvider GetFormatProv(CommandLineArgs args)
		{
			string strFormat = args["format"];
			if(string.IsNullOrEmpty(strFormat))
			{
				KPScript.Program.WriteLineColored("E: Invalid format!", ConsoleColor.Red);
				return null;
			}

			FileFormatPool ffp = KeePass.Program.FileFormatPool;
			FileFormatProvider prov = ffp.Find(strFormat);
			if(prov == null)
			{
				KPScript.Program.WriteLineColored("E: Unknown format!", ConsoleColor.Red);
				return null;
			}

			return prov;
		}

		private static bool PerformImport(PwDatabase pwDb, CommandLineArgs args)
		{
			string strFile = args["file"];
			if(string.IsNullOrEmpty(strFile))
			{
				KPScript.Program.WriteLineColored("E: No file specified to import!", ConsoleColor.Red);
				return false;
			}
			IOConnectionInfo ioc = IOConnectionInfo.FromPath(strFile);

			FileFormatProvider prov = GetFormatProv(args);
			if(prov == null) return false;

			if(!prov.SupportsImport)
			{
				KPScript.Program.WriteLineColored("E: No import support for this format!",
					ConsoleColor.Red);
				return false;
			}

			if(!prov.TryBeginImport())
			{
				KPScript.Program.WriteLineColored("E: Format initialization failed!",
					ConsoleColor.Red);
				return false;
			}

			PwMergeMethod mm = PwMergeMethod.CreateNewUuids;
			string strMM = args["mm"];
			if(!string.IsNullOrEmpty(strMM))
			{
				if(strMM.Equals("CreateNewUuids", StrUtil.CaseIgnoreCmp))
					mm = PwMergeMethod.CreateNewUuids;
				else if(strMM.Equals("KeepExisting", StrUtil.CaseIgnoreCmp))
					mm = PwMergeMethod.KeepExisting;
				else if(strMM.Equals("OverwriteExisting", StrUtil.CaseIgnoreCmp))
					mm = PwMergeMethod.OverwriteExisting;
				else if(strMM.Equals("OverwriteIfNewer", StrUtil.CaseIgnoreCmp))
					mm = PwMergeMethod.OverwriteIfNewer;
				else if(strMM.Equals("Sync", StrUtil.CaseIgnoreCmp))
					mm = PwMergeMethod.Synchronize;
			}

			CompositeKey cmpKey = KpsUtil.GetMasterKey(args, "imp_", ioc);
			if((cmpKey == null) || (cmpKey.UserKeyCount == 0))
				cmpKey = pwDb.MasterKey;

			bool? ob = false;
			string strError = "Import failed!";

			try { ob = ImportUtil.Import(pwDb, prov, ioc, mm, cmpKey); }
			catch(Exception ex)
			{
				if((ex != null) && !string.IsNullOrEmpty(ex.Message))
					strError = ex.Message;
			}

			bool r = (ob.HasValue && ob.Value);
			if(r)
				KPScript.Program.WriteLineColored("OK: Import succeeded!", ConsoleColor.Green);
			else
				KPScript.Program.WriteLineColored("E: " + strError, ConsoleColor.Red);
			return r;
		}

		private static void PerformExport(PwDatabase pwDb, CommandLineArgs args)
		{
			FileFormatProvider prov = GetFormatProv(args);
			if(prov == null) return;

			if(!prov.SupportsExport)
			{
				KPScript.Program.WriteLineColored("E: No export support for this format!",
					ConsoleColor.Red);
				return;
			}

			if(!prov.TryBeginExport())
			{
				KPScript.Program.WriteLineColored("E: Format initialization failed!",
					ConsoleColor.Red);
				return;
			}

			FileStream fs;
			try
			{
				fs = new FileStream(args["outfile"], FileMode.Create, FileAccess.Write,
					FileShare.None);
			}
			catch(Exception exFs)
			{
				KPScript.Program.WriteLineColored("E: " + exFs.Message, ConsoleColor.Red);
				return;
			}

			PwGroup pg = pwDb.RootGroup;
			string str = args[EntryMod.ParamGroupPath];
			if(!string.IsNullOrEmpty(str))
			{
				pg = pg.FindCreateSubTree(str, new char[] { '/' }, false);
				if(pg == null)
				{
					KPScript.Program.WriteLineColored(@"E: Group '" + str +
						@"' not found!", ConsoleColor.Red);
					return;
				}
			}

			PwExportInfo pwInfo = new PwExportInfo(pg, pwDb, true);

			str = args[ParamXslFileCL];
			if(!string.IsNullOrEmpty(str))
				pwInfo.Parameters[ParamXslFile] = str;

			if(prov.Export(pwInfo, fs, null))
				KPScript.Program.WriteLineColored("OK: Export succeeded!", ConsoleColor.Green);
			else
				KPScript.Program.WriteLineColored("E: Export failed!", ConsoleColor.Red);
		}

		private static void PerformSync(PwDatabase pwDb, CommandLineArgs args)
		{
			string strFile = args["file"];
			if(string.IsNullOrEmpty(strFile))
			{
				KPScript.Program.WriteLineColored("E: No file specified to synchronize with!", ConsoleColor.Red);
				return;
			}

			IOConnectionInfo ioc = IOConnectionInfo.FromPath(strFile);

			bool? ob = ImportUtil.Synchronize(pwDb, new PwDatabaseSaver(pwDb), ioc, true, null);
			if(ob.HasValue && ob.Value)
				KPScript.Program.WriteLineColored("OK: Synchronization succeeded!", ConsoleColor.Green);
			else
				KPScript.Program.WriteLineColored("E: Synchronization failed!", ConsoleColor.Red);
		}
	}
}
