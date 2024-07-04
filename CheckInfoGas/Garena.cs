using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using xNet;
using System;
using System.Net.Http.Headers;
using HttpMethod = System.Net.Http.HttpMethod;

namespace CheckInfoGas
{
    public static class Garena
    {
        public enum StatusLogin
        {
            Ok,
            Ban,
            Empty,
            Auth,
            Spam
        }

        public static (HttpRequest, StatusLogin) CheckLogin(string username, string encryptPassword)
        {
            using (var http = new HttpRequest())
            {
                http.Cookies = new CookieDictionary();
                http.UserAgent = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36";
                http.KeepAlive = true;
                http.EnableEncodingContent = true;

                var response = http.Get($"https://connect.garena.com/api/login?account={username}&password={encryptPassword}&format=json&app_id=10100").ToString();

                if (response.Contains("error_auth"))
                {
                    return (http, StatusLogin.Auth);
                }
                else if (response.Contains("error_suspicious_ip"))
                {
                    return (http, StatusLogin.Spam);
                }
                else if (response.Contains("error_user_ban"))
                {
                    return (http, StatusLogin.Ban);
                }
                else if (string.IsNullOrEmpty(response))
                {
                    return (http, StatusLogin.Empty);
                }

                return (http, StatusLogin.Ok);
            }
        }

        public static UserInfo CheckInfoAccount(HttpRequest http, string proxy)
        {
            var urlCheckInfo = "https://account.garena.com/api/account/init";
            var responseInfo = http.Get(urlCheckInfo).ToString();
            var initObject = JObject.Parse(responseInfo);
            var userInfo = new UserInfo();

            if (initObject.ContainsKey("user_info"))
            {
                var infoStatus = string.Empty;
                var phoneNumber = initObject["user_info"]["mobile_no"].ToString();
                var checkPhone = phoneNumber.Contains("*") ? true : false;

                var emailVerification = initObject["user_info"]["email_v"].ToString();
                var checkEmail = emailVerification.Equals("0") ? false : true;

                var checkFb = string.Empty;
                var testFb = http.Get("https://account.garena.com/fbSecurity/facebookConnect/init#").ToString();
                var fbUid = Regex.Match(responseInfo, "fb_uid\":\"(.*?)\"").Groups[1].Value;
                var fbAccount = Regex.Match(responseInfo, "fb_account\":(.*?)}").Groups[1].Value;
                if (!fbAccount.Equals("null"))
                {
                    var fbAccountObject = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>($"{fbAccount}}}");
                    if (string.IsNullOrEmpty(fbAccountObject["fb_username"].ToString()))
                    {
                        userInfo.isConnectFb = true;
                    }
                }
                else
                {
                    userInfo.isConnectFb = false;
                }

                userInfo.IdCard = string.IsNullOrEmpty(Regex.Match(responseInfo, "idcard\":\"(.*?)\"").Groups[1].Value) ? false : true;

                if (checkPhone == true)
                {
                    userInfo.Status = UserInfo.InfoStatus.FullTT;
                }
                else if (checkEmail == true)
                {
                    userInfo.Status = UserInfo.InfoStatus.Error_Email;
                    checkEmail = true;
                }
                else if (checkEmail == false && checkPhone == false)
                {
                    userInfo.Status = UserInfo.InfoStatus.TTT;
                }



                return userInfo;
            }
            else
            {
                userInfo.Status = UserInfo.InfoStatus.NotExist;
                return userInfo;
            }
        }

        public static string GetTokenGrant(HttpRequest http)
        {
            var payload = "client_id=100054&response_type=token&redirect_uri=https%3A%2F%2Fsale.lienquan.garena.vn%2Flogin%2Fcallback&format=json&id=21435678908765432";
            var response = http.Post("https://auth.garena.com/oauth/token/grant", payload, "application/x-www-form-urlencoded").ToString();
            var responseObject = JObject.Parse(response);
            var token = responseObject["access_token"].ToString();
            return token;
        }

        public static async void LoginFCO(HttpRequest http, string accessToken)
        {
            HttpClientHandler httpHandler = new HttpClientHandler();

            httpHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
            var client = new HttpClient(httpHandler);
            client.DefaultRequestHeaders.Host = "ranking.fconline.garena.vn";
            var request1 = new HttpRequestMessage(HttpMethod.Get, $"https://ranking.fconline.garena.vn/login/callback?access_token={accessToken}");
            var response1 = await client.SendAsync(request1);
            var request = new HttpRequestMessage(HttpMethod.Get, "https://ranking.fconline.garena.vn/api/user/profile");
            var request2 = new HttpRequestMessage(HttpMethod.Get, "https://ranking.fconline.garena.vn/api/user/get");
            var response2 = await client.SendAsync(request2);
            //request.Headers.Add("Cookie", cookieString);
            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            Console.WriteLine(await response.Content.ReadAsStringAsync());

            //            var response = http.Get($"https://ranking.fconline.garena.vn/login/callback?access_token={accessToken}");

            //            var cookies = http.Cookies.ToDictionary();
            //            var desiredCookies = cookies
            //                   .Where(x => x.Key == "csrftoken" || x.Key == "sessionid")
            //                   .ToDictionary(x => x.Key, x => x.Value);
            //            var httpRequest = new HttpRequest();
            //            httpRequest.Cookies = new CookieDictionary();
            //            httpRequest.KeepAlive = true;
            //            httpRequest.AddCookie(desiredCookies);
            //            httpRequest.SslCertificateValidatorCallback +=
            //delegate (object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate,
            //                        System.Security.Cryptography.X509Certificates.X509Chain chain,
            //                        System.Net.Security.SslPolicyErrors sslPolicyErrors)
            //{
            //    return true; // **** Always accept
            //};
            //            httpRequest.AddHeader("X-Csrftoken", desiredCookies["csrftoken"]);
            //            httpRequest.UserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1";
            //            var response2 = httpRequest.Get("https://ranking.fconline.garena.vn/api/user/get").ToString();
            //            var response3 = httpRequest.Get("https://ranking.fconline.garena.vn/api/user/profile");


        }
    }
}
