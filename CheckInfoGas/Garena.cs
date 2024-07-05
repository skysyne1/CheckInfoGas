using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using xNet;

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

        public static void LoginFCO(Dictionary<string, string> Cookies, UserInfo userInfo)
        {
            var http = new HttpRequest
            {
                Cookies = new CookieDictionary(),
            };

            http.AddCookie(Cookies);
            var postData = new Dictionary<string, string>
                {
                    { "client_id", "32837" },
                    { "redirect_uri", "https://ranking.fo4.garena.vn/login/callback" },
                    { "response_type", "token" },
                    { "platform", "1" },
                    { "locale", "vi-VN" }
                };
            var content = new xNet.FormUrlEncodedContent(postData);
            var postResponse = http.Post("https://auth.garena.com/oauth/token/grant", content).ToString();
            var data3 = JObject.Parse(postResponse);
            var link = data3["redirect_uri"].ToString();
            var profileResponse11 = http.Get(link).ToString();
            var profileResponse = http.Get("https://ranking.fo4.garena.vn/api/user/profile").ToString();
            
            var profileObject = JObject.Parse(profileResponse);
            if (profileObject.ContainsKey("payload"))
            {
                var balance = FormatNumberWithComma(profileObject["payload"]["balance"].ToString());
                var teamPrice = FormatNumberWithComma(profileObject["payload"]["team_price"].ToString());
                userInfo.FO4Info = new UserInfo.FO4
                {
                    Balance = balance,
                    TeamValues = teamPrice
                };
            }
        }

        public static UserInfo CheckRankLQ(HttpRequest http, UserInfo userInfo)
        {
            var postData = new Dictionary<string, string>
                {
                    { "client_id", "100054" },
                    { "response_type", "token" },
                    { "redirect_uri", "https://sale.lienquan.garena.vn/login/callback" },
                    { "format", "json" },
                    { "id", "32546780697654" }
                };
            var content = new xNet.FormUrlEncodedContent(postData);
            var postResponse = http.Post("https://auth.garena.com/oauth/token/grant", content).ToString();

            var data3 = JObject.Parse(postResponse);
            var link = data3["redirect_uri"].ToString();
            var token = data3["access_token"].ToString();

            http.Cookies.Add("access-token", token);
            string profileResponse11 = http.Get(link).ToString();
            var postData1 = new
            {
                operationName = "getUser",
                variables = new { },
                query = @"query getUser {
        getUser {
          id
          name
          icon
          profile {
            ownedItemIdList
            __typename
          }
          __typename
        }
      }"
            };

            // Chuyển đối tượng thành chuỗi JSON
            string jsonString = JsonConvert.SerializeObject(postData1);
            string postResponse1 = http.Post("https://sale.lienquan.garena.vn/graphql", jsonString, "application/json").ToString();
            var jsonResponse = JObject.Parse(postResponse1);

            if (jsonResponse["errors"] != null && jsonResponse["errors"].Any(e => e["message"].ToString() == "NOT_LOGIN"))
            {
                return userInfo;
            }

            var ownedItemIdList = jsonResponse["data"]["getUser"]["profile"]["ownedItemIdList"] as JArray;
            int itemCount = ownedItemIdList.Count;
            var name = jsonResponse["data"]["getUser"]["name"];

            var url = "https://weeklyreport.moba.garena.vn/api/profile";
            var headers = new Dictionary<string, string>
                {
                    { "accept", "application/json, text/plain, */*" },
                    { "accept-language", "vi,vi-VN;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5" },
                    { "access-token", token },
                    { "partition", "1011" },
                    { "priority", "u=1, i" },
                    { "referer", "https://weeklyreport.moba.garena.vn/portrait/recall" },
                    { "sec-fetch-dest", "empty" },
                    { "sec-fetch-mode", "cors" },
                    { "sec-fetch-site", "same-origin" },
                    { "user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1" }
                };

            foreach (var header in headers)
            {
                http.AddHeader(header.Key, header.Value);
            }

            string check_rank = http.Get(url).ToString();

            if (check_rank.Contains("ERROR__GAME_LOGIN_FAILED"))
            {
                return userInfo;
            }

            var data = JObject.Parse(check_rank);
            var playerRank = data["player_info"]["rank"].ToString();
            var rankConfig = data["rank_config"] as JObject;
            string rankName = "";

            foreach (var rank in rankConfig)
            {
                if (rank.Key == playerRank)
                {
                    rankName = rank.Value["name"].ToString();
                    break;
                }
            }

            userInfo.LienQuanInfo = new UserInfo.LienQuan
            {
                Name = name.ToString(),
                Rank = rankName,
                Skin = itemCount.ToString()
            };

            return userInfo;
        }

        private static string FormatNumberWithComma(string numberString)
        {
            if (string.IsNullOrEmpty(numberString))
                return "";

            decimal number;
            if (decimal.TryParse(numberString, out number))
            {
                return number.ToString("#,##0");
            }
            return "";
        }
    }
}
