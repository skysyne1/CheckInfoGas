namespace CheckInfoGas
{
    public class UserInfo
    {
        public enum InfoStatus
        {
            FullTT,
            Error_Email,
            TTT,
            NotExist
        }

        public bool EmailLK { get; set; } = false;

        public bool Mobile { get; set; } = false;

        public string FbUid { get; set; }

        public bool isConnectFb { get; set; }

        public bool IdCard { get; set; } = false;

        public InfoStatus Status { get; set; }
    }
}
