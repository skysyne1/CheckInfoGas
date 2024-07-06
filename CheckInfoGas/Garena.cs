using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
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

        public static Task<(HttpRequest, StatusLogin)> CheckLogin(ApiClient apiClient, string username, string encryptPassword)
        {
            return Task.Run(() =>
            {
                string response = apiClient.HttpClient.Get($"https://connect.garena.com/api/login?account={username}&password={encryptPassword}&format=json&app_id=10100").ToString();

                if (response.Contains("error_auth"))
                    return (apiClient.HttpClient, StatusLogin.Auth);
                if (response.Contains("error_suspicious_ip"))
                    return (apiClient.HttpClient, StatusLogin.Spam);
                if (response.Contains("error_user_ban"))
                    return (apiClient.HttpClient, StatusLogin.Ban);
                if (string.IsNullOrEmpty(response))
                    return (apiClient.HttpClient, StatusLogin.Empty);

                return (apiClient.HttpClient, StatusLogin.Ok);
            });
        }

        public static Task<UserInfo> CheckInfoAccount(ApiClient apiClient)
        {
            return Task.Run(() =>
            {
                apiClient.HttpClient.Referer = "";
                var responseInfo = apiClient.HttpClient.Get(Constants.URLCheckInfo).ToString();
                var initObject = JObject.Parse(responseInfo);
                var userInfo = new UserInfo();

                if (initObject.ContainsKey("user_info"))
                {
                    var userInfoObject = initObject["user_info"];
                    var phoneNumber = userInfoObject["mobile_no"].ToString();
                    var emailVerification = userInfoObject["email_v"].ToString();
                    var checkPhone = phoneNumber.Contains("*");
                    var checkEmail = emailVerification != "0";

                    var testFb = apiClient.HttpClient.Get("https://account.garena.com/fbSecurity/facebookConnect/init#").ToString();
                    var fbAccount = Regex.Match(responseInfo, "fb_account\":(.*?)}").Groups[1].Value;

                    if (!fbAccount.Equals("null"))
                    {
                        var fbAccountObject = JsonConvert.DeserializeObject<dynamic>($"{fbAccount}}}");
                        userInfo.isConnectFb = !string.IsNullOrEmpty(fbAccountObject["fb_username"].ToString());
                    }
                    else
                    {
                        userInfo.isConnectFb = false;
                    }

                    userInfo.IdCard = !string.IsNullOrEmpty(Regex.Match(responseInfo, "idcard\":\"(.*?)\"").Groups[1].Value);

                    userInfo.Status = checkPhone ? UserInfo.InfoStatus.FullTT
                                     : checkEmail ? UserInfo.InfoStatus.Error_Email
                                     : UserInfo.InfoStatus.TTT;

                    return userInfo;
                }
                else
                {
                    userInfo.Status = UserInfo.InfoStatus.NotExist;
                    return userInfo;
                }
            });
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

        public static Task<UserInfo> CheckRankLQ(ApiClient apiClient, UserInfo userInfo)
        {
            return Task.Run(() =>
            {
                var token = GetAccessToken(apiClient);
                if (token == null)
                    return userInfo;

                var graphqlResponse = GetGraphQLResponse(apiClient, token);
                if (graphqlResponse == null || graphqlResponse.ContainsKey("errors"))
                    return userInfo;

                var ownedItemIdList = graphqlResponse["data"]["getUser"]["profile"]["ownedItemIdList"] as JArray;
                var name = graphqlResponse["data"]["getUser"]["name"].ToString();

                var playerRank = GetPlayerRank(apiClient, token);
                if (playerRank == null)
                    return userInfo;

                var rankConfig = playerRank["rank_config"] as JObject;
                var playerRankId = playerRank["player_info"]["rank"].ToString();
                var rankName = GetRankName(rankConfig, playerRankId);

                userInfo.LienQuanInfo = new UserInfo.LienQuan
                {
                    Name = name,
                    Rank = rankName,
                    Skin = ownedItemIdList?.Count.ToString() ?? "0"
                };

                return userInfo;
            });
        }

        private static JObject GetAccessToken(ApiClient apiClient)
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
            var postResponse = apiClient.HttpClient.Post("https://auth.garena.com/oauth/token/grant", content).ToString();
            var data = JObject.Parse(postResponse);

            apiClient.HttpClient.Cookies.Add("access-token", data["access_token"].ToString());

            return data;
        }

        private static JObject GetGraphQLResponse(ApiClient apiClient, JObject token)
        {
            var postData = new
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

            string jsonString = JsonConvert.SerializeObject(postData);
            string postResponse = apiClient.HttpClient.Post("https://sale.lienquan.garena.vn/graphql", jsonString, "application/json").ToString();

            return JObject.Parse(postResponse);
        }

        private static JObject GetPlayerRank(ApiClient apiClient, JObject token)
        {
            var url = "https://weeklyreport.moba.garena.vn/api/profile";
            var headers = new Dictionary<string, string>
            {
                { "accept", "application/json, text/plain, */*" },
                { "accept-language", "vi,vi-VN;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5" },
                { "access-token", token["access_token"].ToString() },
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
                apiClient.HttpClient.AddHeader(header.Key, header.Value);
            }

            string check_rank = apiClient.HttpClient.Get(url).ToString();

            return check_rank.Contains("ERROR__GAME_LOGIN_FAILED") ? null : JObject.Parse(check_rank);
        }

        private static string GetRankName(JObject rankConfig, string playerRankId)
        {
            foreach (var rank in rankConfig)
            {
                if (rank.Key == playerRankId)
                {
                    return rank.Value["name"].ToString();
                }
            }
            return "";
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
