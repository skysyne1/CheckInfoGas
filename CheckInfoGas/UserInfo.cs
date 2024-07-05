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

        public FO4 FO4Info { get; set; } = new FO4();

        public LienQuan LienQuanInfo { get; set; } = new LienQuan();

        public InfoStatus? Status { get; set; }

        public class FO4
        {
            public string TeamValues { get; set; }

            public string Balance { get; set; }
        }

        public class LienQuan
        {
            public string Skin { get; set; }

            public string Rank { get; set; }

            public string Name { get; set; }
        }
    }
}
