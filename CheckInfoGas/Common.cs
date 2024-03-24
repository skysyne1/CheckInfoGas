using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

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
    }
}
