#!/system/bin/sh
TD=/data/local/tmp/bl-test
N=1000
echo "bench_file_content" > "$TD/bench_file.txt"
ln -sf "$TD/bench_file.txt" "$TD/bench_link.txt"

echo "=== open x$N ==="
START=$(date +%s%N 2>/dev/null || date +%s)
i=0
while [ $i -lt $N ]; do
	cat "$TD/bench_file.txt" > /dev/null 2>&1
	i=$((i+1))
done
END=$(date +%s%N 2>/dev/null || date +%s)
echo "open: $((END-START)) ns total, $(( (END-START)/N )) ns/op"

echo "=== stat x$N ==="
START=$(date +%s%N 2>/dev/null || date +%s)
i=0
while [ $i -lt $N ]; do
	stat "$TD/bench_file.txt" > /dev/null 2>&1
	i=$((i+1))
done
END=$(date +%s%N 2>/dev/null || date +%s)
echo "stat: $((END-START)) ns total, $(( (END-START)/N )) ns/op"

echo "=== readlink x$N ==="
START=$(date +%s%N 2>/dev/null || date +%s)
i=0
while [ $i -lt $N ]; do
	readlink /proc/self/exe > /dev/null 2>&1
	i=$((i+1))
done
END=$(date +%s%N 2>/dev/null || date +%s)
echo "readlink: $((END-START)) ns total, $(( (END-START)/N )) ns/op"

echo "=== exec x100 ==="
START=$(date +%s%N 2>/dev/null || date +%s)
i=0
while [ $i -lt 100 ]; do
	/system/bin/true
	i=$((i+1))
done
END=$(date +%s%N 2>/dev/null || date +%s)
echo "exec: $((END-START)) ns total, $(( (END-START)/100 )) ns/op"

rm -f "$TD/bench_file.txt" "$TD/bench_link.txt"
