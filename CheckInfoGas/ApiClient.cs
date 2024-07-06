using xNet;

namespace CheckInfoGas
{
    public class ApiClient
    {
        public ApiClient(string proxy)
        {
            if (!string.IsNullOrEmpty(proxy))
            {
                var proxyPart = proxy.Split(':');
                _apiClient.Proxy = HttpProxyClient.Parse($"{proxyPart[0]}:{proxyPart[1]}");

                if (proxyPart.Length >= 4)
                {
                    _apiClient.Proxy.Username = proxyPart[2];
                    _apiClient.Proxy.Password = proxyPart[3];
                }
            }

            InitHeader();
        }

        private readonly HttpRequest _apiClient = new();

        public HttpRequest HttpClient
        {
            get { return _apiClient; }
        }

        private void InitHeader()
        {
            _apiClient.AllowAutoRedirect = true;
            _apiClient.KeepAlive = true;
            _apiClient.EnableEncodingContent = true;
            _apiClient.UserAgent = Constants.UserAgent;
        }
    }
}
