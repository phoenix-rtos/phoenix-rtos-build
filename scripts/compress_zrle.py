#!/usr/bin/env python3
#
# Compress the file using zero run length encoding
#
# Copyright 2025 Phoenix Systems
# Author: Aleksander Kaminski
#
import sys

def compress_zrle(data: bytes) -> bytes:
	out = bytearray()
	i = 0
	n = len(data)

	while i < n:
		b = data[i]
		if b != 0:
			out.append(b)
			i += 1
		else:
			run_len = 0
			while i < n and data[i] == 0:
				run_len += 1
				i += 1

			while run_len != 0:
				chunk = min(run_len, 255)
				out.extend((0, chunk))
				run_len -= chunk

	return bytes(out)


if __name__ == "__main__":
	if len(sys.argv) != 2:
		print(f"Usage: {sys.argv[0]} file")
		sys.exit(1)

	with open(sys.argv[1], "rb") as f:
		data = f.read()

	sys.stdout.buffer.write(compress_zrle(data))
