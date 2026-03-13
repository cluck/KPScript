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
using System.Windows.Forms;

using KeePass.App;
using KeePass.Forms;
using KeePass.Util;

using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KPScript
{
	public static class KpsUtil
	{
		private const string ParamGuiKey = "guikeyprompt";
		private const string ParamConsoleKey = "keyprompt";

		public static CompositeKey GetMasterKey(CommandLineArgs args,
			string strPrefix, IOConnectionInfo ioc)
		{
			if(args == null) throw new ArgumentNullException("args");

			string strPre = (strPrefix ?? string.Empty);

			if(args[strPre + ParamGuiKey] != null)
			{
				KeyPromptForm kpf = new KeyPromptForm();
				kpf.InitEx(ioc, false, false);
				if(kpf.ShowDialog() != DialogResult.OK) return null;

				return kpf.CompositeKey;
			}

			if(args[strPre + ParamConsoleKey] != null)
			{
				CompositeKey cmpKey = new CompositeKey();

				Console.WriteLine(KSRes.NoKeyPartHint);
				Console.WriteLine();
				Console.WriteLine(KSRes.KeyPrompt);

				Console.Write(KSRes.PasswordPrompt + " ");
				string strPw = Console.ReadLine().Trim();
				if((strPw != null) && (strPw.Length > 0))
					cmpKey.AddUserKey(new KcpPassword(strPw));

				Console.Write(KSRes.KeyFilePrompt + " ");
				string strFile = Console.ReadLine().Trim();
				if((strFile != null) && (strFile.Length > 0))
					cmpKey.AddUserKey(new KcpKeyFile(strFile));

				Console.Write(KSRes.UserAccountPrompt + " ");
				string strUA = Console.ReadLine().Trim();
				if(strUA != null)
				{
					string strUal = strUA.ToLower();
					if((strUal == "y") || (strUal == "j") ||
						(strUal == "o") || (strUal == "a") ||
						(strUal == "u"))
					{
						cmpKey.AddUserKey(new KcpUserAccount());
					}
				}

				return cmpKey;
			}

			return KpsUtil.KeyFromCommandLine(args, strPre);
		}

		private static CompositeKey KeyFromCommandLine(CommandLineArgs args,
			string strPrefix)
		{
			CompositeKey cmpKey = new CompositeKey();

			string strPw = args[strPrefix + AppDefs.CommandLineOptions.Password];
			string strPwEnc = args[strPrefix + AppDefs.CommandLineOptions.PasswordEncrypted];
			string strFile = args[strPrefix + AppDefs.CommandLineOptions.KeyFile];
			string strUserAcc = args[strPrefix + AppDefs.CommandLineOptions.UserAccount];

			if(strPw != null)
				cmpKey.AddUserKey(new KcpPassword(strPw));
			else if(strPwEnc != null)
				cmpKey.AddUserKey(new KcpPassword(StrUtil.DecryptString(strPwEnc)));

			if(strFile != null)
			{
				/* KeyProviderPool kpp = KeePass.Program.KeyProviderPool;
				if((kpp != null) && kpp.IsKeyProvider(strFile))
				{
					KeyProvider kp = kpp.Get(strFile);
					bool bPerformHash = !kp.DirectKey;
					KeyProviderQueryContext ctxKP = new KeyProviderQueryContext(
						IOConnectionInfo.FromPath(args.FileName), false, false);

					byte[] pbProvKey = kp.GetKey(ctxKP);
					if((pbProvKey == null) || (pbProvKey.Length == 0))
						throw new OperationCanceledException();

					cmpKey.AddUserKey(new KcpCustomKey(strFile, pbProvKey, bPerformHash));
				}
				else */
				cmpKey.AddUserKey(new KcpKeyFile(strFile));
			}

			if(strUserAcc != null)
				cmpKey.AddUserKey(new KcpUserAccount());

			return cmpKey;
		}
	}
}
