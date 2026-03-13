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

using KeePass.App;
using KeePass.Util;

using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Utility;

namespace KPScript.ScriptingModules
{
	public static class DatabaseMod
	{
		private const string CmdChangeMasterKey = "changemasterkey";

		public static bool ProcessCommand(string strCommand, CommandLineArgs args,
			PwDatabase pwDatabase, out bool bNeedsSave)
		{
			bNeedsSave = false;

			if(strCommand == CmdChangeMasterKey)
				bNeedsSave = ChangeMasterKey(pwDatabase, args);
			else return false;

			return true;
		}

		private static bool ChangeMasterKey(PwDatabase pwDatabase, CommandLineArgs args)
		{
			const string strNew = "new";

			CompositeKey ck = new CompositeKey();

			string strPw = args[strNew + AppDefs.CommandLineOptions.Password];
			string strPwEnc = args[strNew + AppDefs.CommandLineOptions.PasswordEncrypted];
			if(strPw != null)
				ck.AddUserKey(new KcpPassword(strPw));
			else if(strPwEnc != null)
				ck.AddUserKey(new KcpPassword(StrUtil.DecryptString(strPwEnc)));

			string strFile = args[strNew + AppDefs.CommandLineOptions.KeyFile];
			if(!string.IsNullOrEmpty(strFile))
				ck.AddUserKey(new KcpKeyFile(strFile));

			string strAcc = args[strNew + AppDefs.CommandLineOptions.UserAccount];
			if(strAcc != null)
				ck.AddUserKey(new KcpUserAccount());

			if(ck.UserKeyCount > 0)
			{
				pwDatabase.MasterKey = ck;
				pwDatabase.MasterKeyChanged = DateTime.UtcNow;
				pwDatabase.MasterKeyChangeForceOnce = false;
				return true;
			}

			return false;
		}
	}
}
