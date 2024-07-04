using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using xNet;

namespace CheckInfoGas
{
    public static class Common
    {
        public static Task ForEachAsync<T>(this IEnumerable<T> sequence, Func<T, Task> action, CancellationTokenSource cancellationTokenSource)
        {
            if (cancellationTokenSource.IsCancellationRequested)
                return Task.CompletedTask;
            return Task.WhenAll(sequence.Select(action));
        }

        public static void AddCookie(this HttpRequest http, Dictionary<string, string> Cookies)
        {
            foreach (var cookie in Cookies)
            {
                try
                {
                    http.Cookies.Add(cookie.Key, cookie.Value);
                }
                catch { }
            }
        }
    }
}
