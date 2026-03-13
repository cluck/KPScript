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
using System.Text.RegularExpressions;

using KeePass.Util;

using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Delegates;
using KeePassLib.Native;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace KPScript.ScriptingModules
{
	public static class EntryMod
	{
		private const string CmdAddEntry = "addentry";
		private const string CmdAddEntries = "addentries";
		private const string CmdEditEntry = "editentry";
		private const string CmdMoveEntry = "moveentry";
		private const string CmdDeleteEntry = "deleteentry";
		private const string CmdDeleteAllEntries = "deleteallentries";

		internal const string ParamGroupName = "GroupName";
		internal const string ParamGroupPath = "GroupPath";
		private const string ParamGroupTree = "GroupTree"; // Obsolete

		private const string ParamIcon = "setx-Icon";
		private const string ParamCustomIcon = "setx-CustomIcon";
		private const string ParamSetExpires = "setx-Expires";
		private const string ParamSetExpiryTime = "setx-ExpiryTime";

		private const string ParamUserNameList = "UserList";
		private const string ParamPasswordList = "PasswordList";
		private const string ParamTitleList = "TitleList";
		private const string ParamNotesList = "NotesList";
		private const string ParamUrlList = "UrlList";

		private const string ParamDeleteAllExisting = "DeleteExisting";

		private const string ParamCreateBackup = "CreateBackup";

		public static bool ProcessCommand(string strCommand, CommandLineArgs args,
			PwDatabase pwDatabase, out bool bNeedsSave)
		{
			bNeedsSave = false;

			if(strCommand == CmdAddEntry)
				bNeedsSave = AddEntry(pwDatabase, args);
			else if(strCommand == CmdAddEntries)
				bNeedsSave = AddEntries(pwDatabase, args);
			else if(strCommand == CmdEditEntry)
				bNeedsSave = EditEntry(pwDatabase, args);
			else if(strCommand == CmdMoveEntry)
				bNeedsSave = MoveEntry(pwDatabase, args);
			else if(strCommand == CmdDeleteEntry)
				bNeedsSave = DeleteEntry(pwDatabase, args);
			else if(strCommand == CmdDeleteAllEntries)
				bNeedsSave = DeleteAllEntries(pwDatabase);
			else return false;

			return true;
		}

		private static bool AddEntry(PwDatabase pd, CommandLineArgs args)
		{
			PwGroup pg = FindCreateGroup(pd, args);

			PwEntry pe = new PwEntry(true, true);
			pg.AddEntry(pe, true);

			SetEntryString(pe, PwDefs.TitleField, args, pd);
			SetEntryString(pe, PwDefs.UserNameField, args, pd);
			SetEntryString(pe, PwDefs.PasswordField, args, pd);
			SetEntryString(pe, PwDefs.UrlField, args, pd);
			SetEntryString(pe, PwDefs.NotesField, args, pd);

			SetEntryIcon(pe, args, pd);
			SetEntryExpiry(pe, args);

			return true;
		}

		private static bool AddEntries(PwDatabase pwDb, CommandLineArgs args)
		{
			string userlistTokens = args[ParamUserNameList];
			if(string.IsNullOrEmpty(userlistTokens))
				throw new Exception(KSRes.UserListNull);
			userlistTokens = userlistTokens.Replace(", ", ",");

			string passwordTokens = args[ParamPasswordList];
			if(string.IsNullOrEmpty(passwordTokens))
				throw new Exception(KSRes.PasswordListNull);
			passwordTokens = passwordTokens.Replace(", ", ",");

			string titleTokens = args[ParamTitleList];
			if(titleTokens != null) titleTokens = titleTokens.Replace(", ", ",");

			string notesTokens = args[ParamNotesList];
			if(notesTokens != null) notesTokens = notesTokens.Replace(", ", ",");

			string urlTokens = args[ParamUrlList];
			if(urlTokens != null) urlTokens = urlTokens.Replace(", ", ",");

			string[] usernameArray = userlistTokens.Split(',');
			string[] passwordArray = passwordTokens.Split(',');
			string[] titleArray = ((titleTokens != null) ? titleTokens.Split(',') : null);
			string[] notesArray = ((notesTokens != null) ? notesTokens.Split(',') : null);
			string[] urlArray = ((urlTokens != null) ? urlTokens.Split(',') : null);

			if(usernameArray.Length != passwordArray.Length)
				throw new Exception(KSRes.ListLengthsDifferentError);
			if((titleTokens != null) && (titleArray.Length != usernameArray.Length))
				throw new Exception(KSRes.ListLengthsDifferentError);
			if((notesTokens != null) && (notesArray.Length != usernameArray.Length))
				throw new Exception(KSRes.ListLengthsDifferentError);
			if((urlTokens != null) && (urlArray.Length != usernameArray.Length))
				throw new Exception(KSRes.ListLengthsDifferentError);

			if(args[ParamDeleteAllExisting] != null) DeleteAllEntries(pwDb);

			PwGroup pg = FindCreateGroup(pwDb, args);

			for(int i = 0; i < usernameArray.Length; ++i)
			{
				PwEntry pe = new PwEntry(true, true);
				pg.AddEntry(pe, true);

				pe.Strings.Set(PwDefs.UserNameField, new ProtectedString(
					pwDb.MemoryProtection.ProtectUserName,
					FilterString(usernameArray[i], false)));
				pe.Strings.Set(PwDefs.PasswordField, new ProtectedString(
					pwDb.MemoryProtection.ProtectPassword,
					FilterString(passwordArray[i], false)));
				if(titleTokens != null)
					pe.Strings.Set(PwDefs.TitleField, new ProtectedString(
						pwDb.MemoryProtection.ProtectTitle,
						FilterString(titleArray[i], false)));
				if(notesTokens != null)
					pe.Strings.Set(PwDefs.NotesField, new ProtectedString(
						pwDb.MemoryProtection.ProtectNotes,
						FilterString(notesArray[i], true)));
				if(urlTokens != null)
					pe.Strings.Set(PwDefs.UrlField, new ProtectedString(
						pwDb.MemoryProtection.ProtectUrl,
						FilterString(urlArray[i], false)));
			}

			return true;
		}

		private static void SetEntryString(PwEntry pe, string strID,
			CommandLineArgs args, PwDatabase pd)
		{
			string str = args[strID];
			if(str == null) return;

			str = FilterString(str, strID);

			bool bProt = pd.MemoryProtection.GetProtection(strID);
			ProtectedString ps = new ProtectedString(bProt, str);
			pe.Strings.Set(strID, ps);
		}

		private static void SetEntryIcon(PwEntry pe, CommandLineArgs args,
			PwDatabase pd)
		{
			string str = args[ParamCustomIcon];
			if(!string.IsNullOrEmpty(str))
			{
				int i;
				if(int.TryParse(str, out i))
				{
					if((i >= 0) && (i < pd.CustomIcons.Count))
					{
						pe.CustomIconUuid = pd.CustomIcons[i].Uuid;
						return;
					}
				}
			}

			str = args[ParamIcon];
			if(!string.IsNullOrEmpty(str))
			{
				int i;
				if(int.TryParse(str, out i))
				{
					if((i >= 0) && (i < (int)PwIcon.Count))
					{
						pe.IconId = (PwIcon)i;
						pe.CustomIconUuid = PwUuid.Zero;
					}
				}
			}
		}

		private static void SetEntryExpiry(PwEntry pe, CommandLineArgs args)
		{
			string strExp = args[ParamSetExpires];
			if(!string.IsNullOrEmpty(strExp))
			{
				bool? obExpires = StrUtil.StringToBool(strExp);
				if(obExpires.HasValue) pe.Expires = obExpires.Value;
			}

			string strDate = args[ParamSetExpiryTime];
			if(!string.IsNullOrEmpty(strDate))
			{
				DateTime dt;
				if(DateTime.TryParse(strDate, out dt)) pe.ExpiryTime = dt;
				else
					throw new FormatException("Failed to parse date/time '" +
						strDate + "'!");
			}
		}

		private static string FilterString(string str, string strFieldID)
		{
			bool bNewLines = ((strFieldID == PwDefs.NotesField) ||
				!PwDefs.IsStandardField(strFieldID));
			return FilterString(str, bNewLines);
		}

		private static string FilterString(string str, bool bAllowNewLines)
		{
			if(string.IsNullOrEmpty(str)) return string.Empty;

			string s = str;
			const string strBS = @"(YW=5rD6x$+/[Qebh*?&";

			s = s.Replace("\\\\", strBS);

			// s = s.Replace("\\\'", "\'");
			// s = s.Replace("\\\"", "\"");
			s = s.Replace("\\n", "\n");
			s = s.Replace("\\r", "\r");
			s = s.Replace("\\t", "\t");
			s = s.Replace("\\v", "\v");

			s = s.Replace("\\", string.Empty);
			s = s.Replace(strBS, "\\");

			if(bAllowNewLines)
				s = StrUtil.NormalizeNewLines(s, !NativeLib.IsUnix());
			else
			{
				s = s.Replace("\r\n", " ");
				s = s.Replace('\r', ' ');
				s = s.Replace('\n', ' ');
			}

			return s;
		}

		private static PwGroup FindCreateGroup(PwGroup pgContainer, string strName)
		{
			PwGroup pgFound = null;

			GroupHandler gh = delegate(PwGroup pg)
			{
				if(pg.Name == strName)
				{
					pgFound = pg;
					return false;
				}

				return true;
			};

			pgContainer.TraverseTree(TraversalMethod.PreOrder, gh, null);

			if(pgFound != null) return pgFound;

			PwGroup pgNew = new PwGroup(true, true, strName, PwIcon.Folder);
			pgContainer.AddGroup(pgNew, true);

			return pgNew;
		}

		private static PwGroup FindCreateGroup(PwDatabase pwDb, CommandLineArgs args)
		{
			PwGroup pgRoot = pwDb.RootGroup;
			if(pgRoot == null) { Debug.Assert(false); return null; }

			string strPath = args[ParamGroupPath];
			if(string.IsNullOrEmpty(strPath))
				strPath = args[ParamGroupTree];
			if(!string.IsNullOrEmpty(strPath))
				return pgRoot.FindCreateSubTree(strPath, new char[] { '/' }, true);

			string strName = args[ParamGroupName];
			if(!string.IsNullOrEmpty(strName))
				return FindCreateGroup(pgRoot, strName);

			return pgRoot;
		}

		private static bool EntryMatches(PwEntry pe, CommandLineArgs args,
			bool bMatchByDefault)
		{
			bool bMatches = bMatchByDefault;

			const string strRef = "ref-";
			foreach(KeyValuePair<string, string> kvpCmd in args.Parameters)
			{
				if(!kvpCmd.Key.StartsWith(strRef, StrUtil.CaseIgnoreCmp)) continue;

				string strCmdK = kvpCmd.Key.Substring(strRef.Length);
				if(strCmdK.Length == 0) continue;
				string strCmdV = kvpCmd.Value;
				if(string.IsNullOrEmpty(strCmdV)) continue;

				bool bFound = false;
				foreach(KeyValuePair<string, ProtectedString> kvpStr in pe.Strings)
				{
					if(string.Equals(kvpStr.Key, strCmdK, StrUtil.CaseIgnoreCmp))
					{
						string strData = kvpStr.Value.ReadString();

						if((strCmdV.Length > 4) && strCmdV.StartsWith("//") &&
							strCmdV.EndsWith("//"))
						{
							Regex rx = new Regex(strCmdV.Substring(2,
								strCmdV.Length - 4), RegexOptions.IgnoreCase);
							if(!rx.IsMatch(strData)) return false;
						}
						else if(strCmdV != strData) return false;

						bFound = true;
					}
				}
				if(!bFound) return false;

				bMatches = true;
			}

			string strAll = args["refx-All"];
			if(strAll != null) bMatches = true;

			string strValue = args["refx-UUID"];
			if(!string.IsNullOrEmpty(strValue))
			{
				if(!strValue.Equals(pe.Uuid.ToHexString(), StrUtil.CaseIgnoreCmp))
					return false;
				bMatches = true;
			}

			strValue = args["refx-Tags"];
			if(!string.IsNullOrEmpty(strValue))
			{
				string[] vReqTags = strValue.Split(',');
				foreach(string strReqTag in vReqTags)
				{
					string strTag = strReqTag.Trim();
					if(strTag.Length == 0) continue;

					if(!pe.HasTag(strTag)) return false;
					bMatches = true;
				}
			}

			strValue = args["refx-Expires"];
			if(!string.IsNullOrEmpty(strValue))
			{
				bool bExpW = StrUtil.StringToBool(strValue);
				if(pe.Expires != bExpW) return false;
				bMatches = true;
			}

			strValue = args["refx-Expired"];
			if(!string.IsNullOrEmpty(strValue))
			{
				bool bExpW = StrUtil.StringToBool(strValue);
				bool bExpE = (pe.Expires && (pe.ExpiryTime <= DateTime.Now));
				if(bExpE != bExpW) return false;
				bMatches = true;
			}

			strValue = args["refx-Group"];
			PwGroup pgParent = pe.ParentGroup;
			if(!string.IsNullOrEmpty(strValue) && (pgParent != null))
			{
				if(!strValue.Equals(pgParent.Name, StrUtil.CaseIgnoreCmp))
					return false;
				bMatches = true;
			}

			strValue = args["refx-GroupPath"];
			if(!string.IsNullOrEmpty(strValue) && (pgParent != null))
			{
				if(!strValue.Equals(pgParent.GetFullPath("/", false),
					StrUtil.CaseIgnoreCmp))
					return false;
				bMatches = true;
			}

			return bMatches;
		}

		internal static List<PwEntry> FindEntries(PwDatabase pwDb, CommandLineArgs args,
			bool bMatchByDefault)
		{
			List<PwEntry> l = new List<PwEntry>();

			EntryHandler eh = delegate(PwEntry pe)
			{
				if(EntryMatches(pe, args, bMatchByDefault)) l.Add(pe);
				return true;
			};

			pwDb.RootGroup.TraverseTree(TraversalMethod.PreOrder, null, eh);
			return l;
		}

		private static List<KeyValuePair<string, string>> GetNewStrings(CommandLineArgs args)
		{
			List<KeyValuePair<string, string>> l = new List<KeyValuePair<string, string>>();

			foreach(KeyValuePair<string, string> kvp in args.Parameters)
			{
				string strKey = kvp.Key;
				if(strKey.StartsWith("set-", StrUtil.CaseIgnoreCmp) && (strKey.Length > 4))
					l.Add(new KeyValuePair<string, string>(strKey.Substring(4),
						kvp.Value));
			}

			return l;
		}

		private static bool EditEntry(PwDatabase pd, CommandLineArgs args)
		{
			List<KeyValuePair<string, string>> lStrings = GetNewStrings(args);

			List<PwEntry> lEntries = FindEntries(pd, args, false);
			foreach(PwEntry pe in lEntries)
			{
				if(args[ParamCreateBackup] != null) pe.CreateBackup(pd);

				foreach(KeyValuePair<string, string> kvp in lStrings)
				{
					string strKey = kvp.Key;
					foreach(KeyValuePair<string, ProtectedString> kvpItem in pe.Strings)
					{
						if(string.Equals(kvpItem.Key, strKey, StrUtil.CaseIgnoreCmp))
							strKey = kvpItem.Key; // Get correct character case
					}

					pe.Strings.Set(strKey, new ProtectedString(false,
						FilterString(kvp.Value, strKey)));
				}

				SetEntryIcon(pe, args, pd);
				SetEntryExpiry(pe, args);

				pe.Touch(true, false);
			}

			return (lEntries.Count > 0);
		}

		private static bool MoveEntry(PwDatabase pwDb, CommandLineArgs args)
		{
			PwGroup pgTarget = FindCreateGroup(pwDb, args);

			List<PwEntry> lEntries = FindEntries(pwDb, args, false);
			foreach(PwEntry pe in lEntries)
			{
				PwGroup pg = pe.ParentGroup;
				if(pg != null) pg.Entries.Remove(pe);
				else { Debug.Assert(false); }

				pgTarget.AddEntry(pe, true, true);
			}

			return (lEntries.Count > 0);
		}

		private static void DeleteEntries(List<PwEntry> l, PwDatabase pwDb)
		{
			DateTime dtNow = DateTime.Now;

			foreach(PwEntry pe in l)
			{
				PwGroup pg = pe.ParentGroup;
				if(pg != null)
				{
					if(pg.Entries.Remove(pe))
					{
						PwDeletedObject o = new PwDeletedObject(pe.Uuid, dtNow);
						pwDb.DeletedObjects.Add(o);
					}
					else { Debug.Assert(false); }
				}
				else { Debug.Assert(false); }
			}
		}

		private static bool DeleteEntry(PwDatabase pwDb, CommandLineArgs args)
		{
			List<PwEntry> l = FindEntries(pwDb, args, false);
			DeleteEntries(l, pwDb);
			return (l.Count > 0);
		}

		private static bool DeleteAllEntries(PwDatabase pwDb)
		{
			PwObjectList<PwEntry> pwEntries = pwDb.RootGroup.GetEntries(true);
			List<PwEntry> l = pwEntries.CloneShallowToList();
			DeleteEntries(l, pwDb);
			return (l.Count > 0);
		}
	}
}
