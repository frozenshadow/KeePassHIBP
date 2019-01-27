using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassLib.Serialization;
using KeePassLib.Utility;
using KeePassLib.Collections;

namespace KeePassHIBP
{
    class EntryHash
    {
        public EntryHash(KeePassLib.PwEntry entry)
        {
            Entry = entry;
            CalculateHashString();
        }

        public KeePassLib.PwEntry Entry { get; } = null;
        public string Hash { get; private set; } = "";

        public string GetFirst5HashChars()
        {
            return Hash.Substring(0, 5);
        }

        public string GetRemainingHashChars()
        {
            return Hash.Substring(5);
        }

        private void CalculateHashString()
        {
            ProtectedStringDictionary stringDict = Entry.Strings;
            byte[] pw = StrUtil.Utf8.GetBytes(stringDict.ReadSafe(KeePassLib.PwDefs.PasswordField));
            byte[] hashed = null;
            using (SHA1 sha1 = new SHA1Managed())
            {
                hashed = sha1.ComputeHash(pw);
            }
            MemUtil.ZeroByteArray(pw);
            Hash = MemUtil.ByteArrayToHexString(hashed);
            MemUtil.ZeroByteArray(hashed);
        }
    }

	public class KeePassHIBPExt : Plugin
	{
        private IPluginHost m_host = null;

		public override Image SmallIcon
		{
			get { return Properties.Resources.B16x16_Icon; }
		}

		public override string UpdateUrl
		{
			get { return "https://github.com/JanisEst/KeePassHIBP/raw/master/keepass.version"; }
		}

		public override bool Initialize(IPluginHost host)
		{
            if (host == null) return false;
            m_host = host;

			//Debugger.Launch();

			// Workaround to support Tsl1.2 on .NET 4.0
			ServicePointManager.Expect100Continue = true;
			ServicePointManager.SecurityProtocol |= (SecurityProtocolType)768 | (SecurityProtocolType)3072;

			GlobalWindowManager.WindowAdded += WindowAddedHandler;

			return true;
		}

		public override void Terminate()
		{
			GlobalWindowManager.WindowAdded -= WindowAddedHandler;
		}

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            ToolStripMenuItem menuitem = null;

            if (t == PluginMenuType.Entry)
            {
                menuitem = new ToolStripMenuItem
                {
                    Text = "Have I been pwned?"
                };
                menuitem.Image = SmallIcon;
                menuitem.Click += OnCheckSingleEntriesClicked;
                menuitem.Paint += OnCheckSingleEntriesVisibility;
            }
            else if (t == PluginMenuType.Group)
            {
                menuitem = new ToolStripMenuItem
                {
                    Text = "Have I been pwned? (Check group)"
                };
                menuitem.Image = SmallIcon;
                menuitem.Click += OnCheckGroupClicked;
            }

            return menuitem;
        }

        private void OnCheckSingleEntriesVisibility(object sender, EventArgs e)
        {
            if (sender is ToolStripMenuItem menuitem)
            {
                menuitem.Enabled = m_host.MainWindow.GetSelectedEntriesCount() > 0;
            }
        }

        private void OnCheckSingleEntriesClicked(object sender, EventArgs e)
        {
            KeePassLib.PwEntry[] entries = m_host.MainWindow.GetSelectedEntries();
            if (entries == null) return;
            PwObjectList<KeePassLib.PwEntry> list = PwObjectList<KeePassLib.PwEntry>.FromArray(entries);
            CheckEntries(list);
        }

        private void OnCheckGroupClicked(object sender, EventArgs e)
        {
            KeePassLib.PwGroup grp = m_host.MainWindow.GetSelectedGroup();
            if (grp == null) return;
            PwObjectList<KeePassLib.PwEntry> list = grp.GetEntries(true);
            CheckEntries(list);
        }

        private void CheckEntries(PwObjectList<KeePassLib.PwEntry> list)
        {
            List<EntryHash> hashList = new List<EntryHash>();
            foreach (KeePassLib.PwEntry entry in list)
            {
                hashList.Add(new EntryHash(entry));
            }

            HashSet<string> queryHashes = new HashSet<string>();

            foreach (EntryHash eh in hashList)
            {
                queryHashes.Add(eh.GetFirst5HashChars());
            }

            List<string> overallResult = new List<string>();

            const string ApiUrl = "https://api.pwnedpasswords.com/range/";
            foreach (string shortHash in queryHashes)
            {
                string first5Chars = shortHash.Substring(0, 5);
                string result = DownloadString(ApiUrl + first5Chars);

                result = StrUtil.NormalizeNewLines(result, false);

                const int Sha1SuffixLength = 35;

                overallResult.AddRange(result
                    .Split('\n')
                    .Where(l => l.Length >= Sha1SuffixLength)
                    .Select(l => first5Chars + l)
                    .ToList()
                    );
            }

            List<string> textResult = new List<string>();
            foreach (EntryHash eh in hashList)
            {
                string found = overallResult.Find(x => x.Contains(eh.Hash));
                if (found != null)
                {
                    string t = "Password of entry \"" + eh.Entry.Strings.ReadSafe(KeePassLib.PwDefs.TitleField) + "\" was pwned "
                        + found.Substring(found.IndexOf(':') + 1) + " time(s).";
                    textResult.Add(t);
                }
            }

            MessageService.ShowInfoEx("Checked "+hashList.Count.ToString()+" password(s)", String.Join("\n", textResult.ToArray()));
        }

        /// <summary>
        /// Used to modify other form when they load.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void WindowAddedHandler(object sender, GwmWindowEventArgs e)
		{
			if (e.Form is PwEntryForm || e.Form is KeyCreationForm)
			{
				e.Form.Shown += delegate
				{
					var fieldInfo = e.Form.GetType().GetField("m_icgPassword", BindingFlags.Instance | BindingFlags.NonPublic);
					if (fieldInfo != null)
					{
						var icg = fieldInfo.GetValue(e.Form) as PwInputControlGroup;
						if (icg != null)
						{
							var m_tbPassword = e.Form.Controls.Find("m_tbPassword", true).FirstOrDefault() as TextBox;
							if (m_tbPassword != null)
							{
								m_tbPassword.TextChanged += new DelayedEventHandler(TimeSpan.FromMilliseconds(500), delegate
								{
									var pwBytes = icg.GetPasswordUtf8();
									var hash = CreateSha1Hash(pwBytes);
									MemUtil.ZeroByteArray(pwBytes);

									ThreadPool.QueueUserWorkItem(delegate(object oHash)
									{
										var strHash = (string)oHash;
										try
										{
											var knownHashes = RequestPwnedHashes(strHash);

											if (knownHashes.Contains(hash))
											{
												m_tbPassword.Invoke((MethodInvoker)delegate
												{
													var toolTip = new ToolTip();
													var pt = new Point(0, 0);
													pt.Offset(0, m_tbPassword.Height + 1);
													toolTip.Show("Warning: This password has previously appeared in a data breach.", m_tbPassword, pt, 2500);
												});
											}
										}
										catch
										{
											// Service may not be available.
										}
									}, hash);

									MemUtil.ZeroByteArray(pwBytes);
								}).OnDelay;
							}
						}
					}
				};
			}
		}

		private static List<string> RequestPwnedHashes(string hash)
		{
			const string ApiUrl = "https://api.pwnedpasswords.com/range/";

			var first5Chars = hash.Substring(0, 5);

			var result = DownloadString(ApiUrl + first5Chars);

			result = StrUtil.NormalizeNewLines(result, false);

			const int Sha1SuffixLength = 35;

			return result
				.Split('\n')
				.Where(l => l.Length >= Sha1SuffixLength)
				.Select(l => first5Chars + l.Substring(0, Sha1SuffixLength))
				.ToList();
		}

		private static string DownloadString(string url)
		{
			var ioc = IOConnectionInfo.FromPath(url);

			using (var s = IOConnection.OpenRead(ioc))
			{
				if (s == null)
				{
					throw new InvalidOperationException();
				}

				using (var ms = new MemoryStream())
				{
					MemUtil.CopyStream(s, ms);

					return StrUtil.Utf8.GetString(ms.ToArray());
				}
			}
		}

		private static string CreateSha1Hash(byte[] data)
		{
			using (var sha1 = new SHA1Managed())
			{
				var hash = sha1.ComputeHash(data);

				return MemUtil.ByteArrayToHexString(hash);
			}
		}
	}
}
