using DeviceId;
using System;
using System.Configuration;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CheckInfoGas
{
    public partial class fCheckKey : Form
    {
        public fCheckKey()
        {
            InitializeComponent();
        }

        private string Permission { get; set; }

        private void fCheckKey_Load(object sender, EventArgs e)
        {
            Onload();
        }

        private async void Onload()
        {
            var licenseKey = GetHardWare();
            tbKey.Text = licenseKey;
            var (status, date) = await CheckKey(licenseKey);
            if (status == true)
            {
                this.Hide();
                new Form1(permission: Permission).Show();
            }
        }

        private async Task<(bool, DateTime?)> CheckKey(string licenseKey)
        {
            var response = await new WebClient().DownloadStringTaskAsync(new Uri("https://docs.google.com/spreadsheets/d/19vkERubz9z2qw8nEWRoYdribSIN5gFCGcgIjOKDikuk/edit#gid=0"));
            var data = Regex.Match(response, $"\\\"{licenseKey}(.*?)\"").Groups[1].Value.Split('|');
            if (data.Length < 2)
            {
                MessageBox.Show($"Vui lòng liên hệ admin để kích hoạt key\n Key của bạn là: {licenseKey} đã được gán vào clipboard", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Clipboard.SetText(licenseKey);
                return (false, null);
            }
            var date = DateTime.Parse(data[1].Replace("\\", "").Replace("n", ""));
            if (DateTime.Now > date.AddDays(1))
            {
                MessageBox.Show($"Vui lòng liên hệ admin để kích hoạt key\n Key của bạn là: {licenseKey} đã được gán vào clipboard", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Clipboard.SetText(licenseKey);
                return (false, date);
            }
            else
            {
                Permission = data[2].Replace("\\", "");
                return (true, date);
            }
        }

        private string GetMD5(string str)
        {
            MD5 mD = MD5.Create();
            byte[] array = mD.ComputeHash(Encoding.UTF8.GetBytes(str));
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < array.Length; i++)
            {
                stringBuilder.Append($"{array[i]:x2}");
            }
            return stringBuilder.ToString();
        }

        private string GetHardWare()
        {
            string deviceId = new DeviceIdBuilder()
                .AddMachineName()
                .AddOsVersion()
                .AddUserName()
                .ToString();
            return GetMD5(EncryptHDD(deviceId, useHashing: true)).ToUpper();
        }

        private string EncryptHDD(string toEncrypt, bool useHashing)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(toEncrypt);
            new AppSettingsReader();
            string s = "#ShynDeepTry#";
            byte[] key;
            if (useHashing)
            {
                MD5CryptoServiceProvider mD5CryptoServiceProvider = new MD5CryptoServiceProvider();
                key = mD5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(s));
                mD5CryptoServiceProvider.Clear();
            }
            else
            {
                key = Encoding.UTF8.GetBytes(s);
            }
            TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
            tripleDESCryptoServiceProvider.Key = key;
            tripleDESCryptoServiceProvider.Mode = CipherMode.ECB;
            tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;
            ICryptoTransform cryptoTransform = tripleDESCryptoServiceProvider.CreateEncryptor();
            byte[] array = cryptoTransform.TransformFinalBlock(bytes, 0, bytes.Length);
            tripleDESCryptoServiceProvider.Clear();
            return Convert.ToBase64String(array, 0, array.Length);
        }

        private void btnReload_Click(object sender, EventArgs e)
        {
            Onload();
        }
    }
}
