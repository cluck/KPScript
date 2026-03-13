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
using System.Text;
using System.Resources;
using System.Diagnostics;

using KeePass.Util;

using KeePassLib.Cryptography;
using KeePassLib.Cryptography.PasswordGenerator;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace KPScript.ScriptingModules
{
	public static class FnMod
	{
		private const string CmdGenPw = "genpw";
		private const string CmdEstQuality = "estimatequality";

		private const string ParamProfile = "profile";
		private const string ParamCount = "count";
		private const string ParamText = "text";

		public static bool ProcessCommand(string strCommand, CommandLineArgs args)
		{
			if(strCommand == CmdGenPw)
				GenPw(args);
			else if(strCommand == CmdEstQuality)
				EstimateQuality(args);
			else return false;

			return true;
		}

		private static void GenPw(CommandLineArgs args)
		{
			List<PwProfile> l = PwGeneratorUtil.GetAllProfiles(false);

			PwProfile pp = null;
			string strProfile = args[ParamProfile];
			if(!string.IsNullOrEmpty(strProfile))
			{
				foreach(PwProfile ppEnum in l)
				{
					if(strProfile.Equals(ppEnum.Name, StrUtil.CaseIgnoreCmp))
					{
						pp = ppEnum;
						break;
					}
				}
			}
			if(pp == null) pp = new PwProfile();

			string strCount = args[ParamCount];
			int iCount = 1;
			if(!string.IsNullOrEmpty(strCount))
			{
				if(!int.TryParse(strCount, out iCount)) iCount = 1;
			}
			if(iCount < 0) iCount = 1;

			for(int i = 0; i < iCount; ++i)
			{
				try
				{
					ProtectedString ps;
					PwGenerator.Generate(out ps, pp, null,
						KeePass.Program.PwGeneratorPool);

					if(ps != null)
					{
						string str = ps.ReadString();
						if(!string.IsNullOrEmpty(str))
							Console.WriteLine(str);
					}
				}
				catch(Exception) { }
			}
		}

		private static void EstimateQuality(CommandLineArgs args)
		{
			string str = args[ParamText];
			if(string.IsNullOrEmpty(str))
			{
				Console.WriteLine("0");
				return;
			}

			try
			{
				ResourceManager rm = KeePass.Program.Resources;
				byte[] pbData = (byte[])rm.GetObject("MostPopularPasswords");
				if(pbData != null)
					PopularPasswords.Add(pbData, true);
				else { Debug.Assert(false); }
			}
			catch(Exception) { Debug.Assert(false); return; }

			uint uBits = QualityEstimation.EstimatePasswordBits(
				str.ToCharArray());
			Console.WriteLine(uBits);
		}
	}
}
