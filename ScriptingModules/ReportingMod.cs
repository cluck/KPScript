/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2026 Dominik Reichl <dominik.reichl@t-online.de>

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

using KeePass.Util;
using KeePass.Util.Spr;

using KeePassLib;
using KeePassLib.Delegates;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace KPScript.ScriptingModules
{
	public static class ReportingMod
	{
		private const string CmdListGroups = "listgroups";
		private const string CmdListEntries = "listentries";
		private const string CmdGetEntryString = "getentrystring";

		private const string ParamField = "Field";

		private const string ParamFailIfNotExists = "FailIfNotExists";
		private const string ParamFailIfNoEntry = "FailIfNoEntry";
		private const string ParamSprCompile = "Spr";

		public static bool ProcessCommand(string strCommand, CommandLineArgs args,
			PwDatabase pwDatabase, out bool bNeedsSave)
		{
			bNeedsSave = false;

			if(strCommand == CmdListGroups)
				ListGroups(pwDatabase);
			else if(strCommand == CmdListEntries)
				ListEntries(pwDatabase, args);
			else if(strCommand == CmdGetEntryString)
				bNeedsSave = GetEntryString(pwDatabase, args);
			else return false;

			return true;
		}

		private static void ListGroups(PwDatabase pwDb)
		{
			GroupHandler gh = delegate(PwGroup pg)
			{
				Console.WriteLine("UUID: " + pg.Uuid.ToHexString());
				Console.WriteLine("N: " + pg.Name);
				Console.WriteLine("I: " + ((uint)pg.IconId).ToString());
				PrintTimes(pg);
				Console.WriteLine("DATS: " + pg.DefaultAutoTypeSequence);
				Console.WriteLine("IE: " + (pg.IsExpanded ? "True" : "False"));

				PwGroup pgParent = pg.ParentGroup;
				Console.WriteLine("PID: " + ((pgParent != null) ?
					pgParent.Uuid.ToHexString() : string.Empty));

				Console.WriteLine();
				return true;
			};

			pwDb.RootGroup.TraverseTree(TraversalMethod.PreOrder, gh, null);
		}

		private static void ListEntries(PwDatabase pwDb, CommandLineArgs args)
		{
			List<PwEntry> l = EntryMod.FindEntries(pwDb, args, true);

			foreach(PwEntry pe in l)
			{
				Console.WriteLine("UUID: " + pe.Uuid.ToHexString());
				Console.WriteLine("GRPU: " + pe.ParentGroup.Uuid.ToHexString());
				Console.WriteLine("GRPN: " + pe.ParentGroup.Name);

				foreach(KeyValuePair<string, ProtectedString> kvp in pe.Strings)
				{
					Console.WriteLine("S: " + kvp.Key + " = " + kvp.Value.ReadString());
				}

				PrintTimes(pe);

				Console.WriteLine();
			}
		}

		private static void PrintTimes(ITimeLogger tl)
		{
			if(tl == null) { Debug.Assert(false); return; }

			Console.WriteLine("TC: " + TimeUtil.SerializeUtc(tl.CreationTime));
			// Console.WriteLine("TLA: " + TimeUtil.SerializeUtc(tl.LastAccessTime));
			Console.WriteLine("TLM: " + TimeUtil.SerializeUtc(tl.LastModificationTime));
			Console.WriteLine("TE: " + TimeUtil.SerializeUtc(tl.ExpiryTime));
			Console.WriteLine("EXP: " + (tl.Expires ? "True" : "False"));
		}

		private static bool GetEntryString(PwDatabase pwDb, CommandLineArgs args)
		{
			string strField = args[ParamField];
			if(string.IsNullOrEmpty(strField))
				throw new ArgumentNullException(ParamField);

			List<PwEntry> l = EntryMod.FindEntries(pwDb, args, false);
			if((args[ParamFailIfNoEntry] != null) && (l.Count == 0))
				throw new Exception(KSRes.EntryNotFound);

			bool bReqExist = (args[ParamFailIfNotExists] != null);
			bool bSprCompile = (args[ParamSprCompile] != null);
			bool bNeedsSave = false;

			foreach(PwEntry pe in l)
			{
				if(bReqExist)
				{
					if(pe.Strings.Get(strField) == null)
						throw new Exception(KSRes.FieldNotFound);
				}

				string strData = pe.Strings.ReadSafe(strField);

				if(bSprCompile)
				{
					SprContext ctx = new SprContext(pe, pwDb, SprCompileFlags.All,
						false, false);
					strData = SprEngine.Compile(strData, ctx);

					bNeedsSave = true;
				}

				Console.WriteLine(strData);
			}

			return bNeedsSave;
		}
	}
}
