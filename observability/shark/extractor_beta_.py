#!/usr/bin/env python3
"""
Modernized tshark extractor script.. reborn.. probably

Extracts files from a pcap file based on tshark output for HTTP, SMB, TFTP, and FTP-DATA streams.

Usage:
  python3 modern_tshark_extractor.py -i capture.pcap -o output_dir [-D "display_filter"]
"""

import argparse
import binascii
import gzip
import os
import sys
import subprocess
from io import BytesIO
from pathlib import Path

def parse_http_stream(fields: list) -> list:
    """
    Parses an HTTP stream from tshark output.

    Args:
        fields (list): List of fields split from the tshark output line.
                       Expected indices:
                         [1]: tcp.reassembled.data
                         [2]: tcp.stream

    Returns:
        A list: [filename, binary data], or None if parsing fails.
    """
    try:
        hex_data = fields[1].replace(":", "").strip("\"")
        file_bytes = binascii.unhexlify(hex_data)
    except Exception:
        return None

    try:
        # Find end of header (assumes HTTP headers end with \r\n\r\n)
        header_end = file_bytes.index(b'\r\n\r\n') + 4
    except ValueError:
        return None

    header = file_bytes[:header_end]
    if b'Content-Encoding: gzip' in header:
        buf = BytesIO(file_bytes[header_end:])
        try:
            with gzip.GzipFile(fileobj=buf) as f:
                file_bytes = f.read()
        except Exception:
            return None
    else:
        file_bytes = file_bytes[header_end:]

    stream_num = fields[2].strip("\"")
    return [f"http_stream_{stream_num}", file_bytes]

def parse_smb_stream(fields: list) -> list:
    """
    Parses an SMB stream from tshark output.

    Args:
        fields (list): List of fields.
                       Expected indices:
                         [3]: smb.fid
                         [4]: smb.file_data

    Returns:
        A list: [filename, binary data]
    """
    try:
        hex_data = fields[4].replace(":", "").strip("\"")
        file_bytes = binascii.unhexlify(hex_data)
    except Exception:
        return None
    fid = fields[3].strip("\"")
    return [f"smb_id_{fid}", file_bytes]

def parse_tftp_stream(fields: list) -> list:
    """
    Parses a TFTP stream from tshark output.

    Args:
        fields (list): List of fields.
                       Expected indices:
                         [5]: data
                         [6]: tftp.source_file or tftp.destination_file

    Returns:
        A list: [filename, binary data]
    """
    try:
        hex_data = fields[5].replace("\"", "").replace(":", "")
        file_bytes = binascii.unhexlify(hex_data)
    except Exception:
        return None
    file_name = f"tftp_stream_{fields[6].strip('\"')}"
    return [file_name, file_bytes]

def extract_files(outdir: str, infile: str, displayfilter: str) -> None:
    """
    Extracts files from the input pcap file using tshark output.

    Args:
        outdir (str): Directory to write extracted files.
        infile (str): Input pcap file.
        displayfilter (str): Optional tshark display filter.
    """
    # Build the tshark command.
    base_cmd = [
        "tshark",
        "-r", infile,
    ]
    filter_expr = "(http.content_length > 0 || (smb.file_data && smb.remaining==0) || ftp-data || tftp.opcode==3)"
    if displayfilter:
        filter_expr = f"{displayfilter} && {filter_expr}"
    base_cmd.extend(["-Y", filter_expr])
    base_cmd.extend([
        "-T", "fields",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.reassembled.data",
        "-e", "tcp.stream",
        "-e", "smb.fid",
        "-e", "smb.file_data",
        "-e", "data",
        "-e", "tftp.source_file",
        "-e", "tftp.destination_file",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-E", "quote=d",
        "-E", "occurrence=a",
        "-E", "separator=|"
    ])
    
    try:
        result = subprocess.run(base_cmd, check=True, capture_output=True, text=True)
        tshark_output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}", file=sys.stderr)
        return

    reassembled_streams = []
    ftp_data_streams = []
    for line in tshark_output.splitlines():
        fields = line.split("|")
        if not fields or fields[0] == "":
            continue
        protocol = fields[0].strip("\"")
        if protocol in ["HTTP", "HTTP/XML"]:
            parsed = parse_http_stream(fields)
            if parsed:
                # Avoid duplicate filenames by appending a count.
                duplicates = [name for name, _ in reassembled_streams if parsed[0] in name]
                if duplicates:
                    parsed[0] = f"{parsed[0]}_{len(duplicates)}"
                reassembled_streams.append(parsed)
        elif protocol == "SMB":
            parsed = parse_smb_stream(fields)
            if parsed:
                # Append data if filename already exists.
                found = False
                for idx, (fname, fdata) in enumerate(reassembled_streams):
                    if fname == parsed[0]:
                        reassembled_streams[idx][1] += parsed[1]
                        found = True
                        break
                if not found:
                    reassembled_streams.append(parsed)
        elif protocol == "TFTP":
            parsed = parse_tftp_stream(fields)
            if parsed:
                found = False
                for idx, (fname, fdata) in enumerate(reassembled_streams):
                    if fname == parsed[0]:
                        reassembled_streams[idx][1] += parsed[1]
                        found = True
                        break
                if not found:
                    reassembled_streams.append(parsed)
        elif protocol == "FTP-DATA":
            ftp_data_streams.append(fields[2].strip("\""))
        elif protocol:
            print(f"WARNING: Unhandled protocol: {protocol}", file=sys.stderr)

    # Write reassembled streams to files.
    for filename, data in reassembled_streams:
        output_path = Path(outdir) / filename
        try:
            with open(output_path, "wb") as f:
                f.write(data)
            print(f"Extracted file: {output_path}")
        except Exception as e:
            print(f"Error writing file {output_path}: {e}", file=sys.stderr)

    # Process FTP-DATA streams separately.
    for stream_number in ftp_data_streams:
        ftp_cmd = [
            "tshark", "-q", "-n",
            "-r", infile,
            "-z", f"follow,tcp,raw,{stream_number}"
        ]
        try:
            ftp_result = subprocess.run(ftp_cmd, check=True, capture_output=True, text=True)
            ftp_lines = ftp_result.stdout.splitlines()
            if len(ftp_lines) > 8:
                hex_text = ''.join(ftp_lines[6:-2]).strip()
                try:
                    file_bytes = binascii.unhexlify(hex_text)
                    output_path = Path(outdir) / f"ftp_stream_{stream_number}"
                    with open(output_path, "wb") as f:
                        f.write(file_bytes)
                    print(f"Extracted FTP file: {output_path}")
                except Exception as e:
                    print(f"Error processing FTP stream {stream_number}: {e}", file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error running tshark for FTP stream {stream_number}: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="Extract files from a pcap using tshark (HTTP, SMB, TFTP, FTP-DATA streams)."
    )
    parser.add_argument("-o", "--outdir", default="output/", help="Output directory for extracted files")
    parser.add_argument("-i", "--infile", required=True, help="Input pcap file to process")
    parser.add_argument("-D", "--displayfilter", default="", help="Optional tshark display filter")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    extract_files(str(outdir), args.infile, args.displayfilter)

if __name__ == "__main__":
    main()
