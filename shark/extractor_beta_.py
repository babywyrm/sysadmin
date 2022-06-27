#!/usr/bin/python
##
##
## the o/g ; tbh this probably needs to be refactored
## >> https://github.com/rangercha/tshark_extractor <<
########################################################
##

import string
import binascii
import sys
import argparse
import gzip
import os
try:
  from cStringIO import StringIO
except:
  from StringIO import StringIO
from subprocess import check_output

################
################


def parse_http_stream(matching_item):
  """
  Based on a tshark http stream, returns a list item of a file name and binary data
  """
  end_of_header=-1
  file_bytes=binascii.unhexlify(matching_item[1].replace(":","").strip("\""))
  try:
    # Find the end of the response header. This should always be \r\n\r\n to satisfy the HTTP standard.
    end_of_header=file_bytes.index('\r\n\r\n')+4
  except ValueError:
    return
    # Print(matching_item[:end_of_header]).
  if 'Content-Encoding: gzip' in file_bytes[:end_of_header]:
    # Content-Encoding header indicates gzipped content. Try to uncompress.
    buf=StringIO(file_bytes[end_of_header:])
    f = gzip.GzipFile(fileobj=buf)
    file_bytes = f.read()
  else:
    # Not gzipped, just grab the response body.
    file_bytes = file_bytes[end_of_header:]
  # Just base the file name on the stream number.
  return ["http_stream_"+matching_item[2].strip("\""),file_bytes]

def parse_smb_stream(matching_item):
  """
  Based on a tshark smb stream, returns a list item of a file name and binary data
  """
  file_bytes=binascii.unhexlify(matching_item[4].replace(":","").strip("\""))
  # SMB file names are easily extracted from tshark.
  # Use the file name_file id as the name to avoid duplicates.
  return ["smb_id_" + matching_item[3].strip("\""), file_bytes]

def parse_tftp_stream(matching_item):
  """
  Based on a tshark tftp stream, returns a list item of a file name and binary data.
  """
  file_bytes=binascii.unhexlify(matching_item[5].replace('\"','').replace(":",""))
  file_name=""
  # Use either the source_file or destination_file, source port, and destination port for the file name.

  file_name="tftp_stream_" + matching_item[6].strip("\"")

  return [file_name,file_bytes]

def extract_files(outdir, infile, displayfilter):
  """
  Based on command line arguments, extracts files to the specified directory
  """
  # Extract all the stream numbers containing the specified display filter.
  # Return stream numbers and the reassembled data. We'll use the stream number in the file name so it can be found in wireshark later if necessary.
  # Return columns.
  # Used to determine protocol:
  # [0]:_ws.col.Protocol
  # Used by HTTP:
  # [1]:tcp.reassembled.data
  # Used by HTTP and FTP:
  # [2]:tcp.stream
  # Used by SMB:
  # [3]:smb.fid
  # [4]:smb.file_data
  # Used by TFTP:
  # [5]:data
  # [6]:udp.stream

  if displayfilter=='':
    hex_stream_data_list = check_output(["tshark", "-r", infile, "-Y", "(http.content_length > 0 || (smb.file_data && smb.remaining==0) || ftp-data || tftp.opcode==3)", "-T", "fields", "-e", "_ws.col.Protocol", "-e", "tcp.reassembled.data", "-e", "tcp.stream", "-e", "smb.fid", "-e", "smb.file_data","-e", "data", "-e", "tftp.source_file", "-e", "tftp.destination_file", "-e", "udp.srcport", "-e", "udp.dstport", "-E", "quote=d","-E", "occurrence=a", "-E", "separator=|"]).split()
  else:
    hex_stream_data_list = check_output(["tshark", "-r", infile, "-Y", displayfilter + " && (http.content_length > 0 || (smb.file_data && smb.remaining==0) || ftp-data || tftp.opcode==3)", "-T", "fields", "-e", "_ws.col.Protocol", "-e", "tcp.reassembled.data", "-e", "tcp.stream", "-e", "smb.fid", "-e", "smb.file_data","-e", "data", "-e", "tftp.source_file", "-e", "tftp.destination_file", "-e", "udp.srcport", "-e", "udp.dstport", "-E", "quote=d","-E", "occurrence=a", "-E", "separator=|"]).split()

  ftp_data_streams=[]
  reassembled_streams=[]
  # Tshark returns stream numbers with no data sometimes. So, we'll find the items with hex encoded data and convert them to their normal binary values.
  # When only take the stream info that immediately follows the data to avoid the extraneous items.
  for matching_item in hex_stream_data_list:
    x_item=matching_item.split("|")
    x_protocol=x_item[0].strip("\"")
    # Pick a parsing method based on the protocol as defined by tshark.
    if (x_protocol=='HTTP' or x_protocol=='HTTP/XML'):
      # Use HTTP parsing method.
      parsed_stream = parse_http_stream(x_item)
      # Parse_http_stream can trap partial streams and return a None value.
      if parsed_stream is not None:
        # We have a valid stream. search the list of previous streams. Create a list of all files coming from the current stream.
        search_index=[x for x,y in enumerate(reassembled_streams) if parsed_stream[0] in y[0]]
        if len(search_index)>0:
          # If we found a match, then we need to modify our filename so we don't overwrite the others.
          parsed_stream[0]=parsed_stream[0]+"_"+str(len(search_index))
        # Add the file to the list of extracted files.
        reassembled_streams.append(parsed_stream)
    elif x_protocol=='SMB':
      # Use SMB parsing method.
      parsed_stream = parse_smb_stream(x_item)
      # Search the previous streams. Create a list of matching file names.
      search_index=[x for x,y in enumerate(reassembled_streams) if (y[0])==parsed_stream[0]]
      if len(search_index)>0:
        # If the file name already exists, append the raw bytes to those of the existing file.
        reassembled_streams[search_index[0]][1]=reassembled_streams[search_index[0]][1]+parsed_stream[1]
      else:
        # The file has not yet had any packets parsed out, start a new reassembled stream.
        reassembled_streams.append(parsed_stream)
    elif x_protocol=='TFTP':
      # Use TFTP parsing method.
      parsed_stream = parse_tftp_stream(x_item)
      # Search the previous streams. Create a list of matching file names.
      search_index=[x for x,y in enumerate(reassembled_streams) if (y[0])==parsed_stream[0]]
      if len(search_index)>0:
        # If the file name already exists, append the raw bytes to those of the existing file.
        reassembled_streams[search_index[0]][1]=reassembled_streams[search_index[0]][1]+parsed_stream[1]
      else:
        # The file has not yet had any packets parsed out, start a new reassembled stream.
        reassembled_streams.append(parsed_stream)
    elif x_protocol=='FTP-DATA':
      # FTP streams are handled in a totally different method.
      ftp_data_streams.append(x_item[2].strip("\""))
    elif x_protocol!='':
      # This shouldn't be possible, display a warning message.
      print("WARNING: untrapped protocol: ---" + x_protocol + "---\n")

  for reassembled_item in reassembled_streams:
    # Write all reassembled streams to files.
    fh=open(os.path.join(outdir,reassembled_item[0]),'w')
    fh.write(reassembled_item[1])
    fh.close()

  for stream_number in ftp_data_streams:
    # Handle FTP streams.
    # For each stream, rerun tshark to extract raw data from the stream.
    hex_stream_list = check_output(["tshark", "-q", "-n", "-r", infile, "-z", "follow,tcp,raw," + stream_number]).split("\n")
    list_length = len(hex_stream_list)
    # Strip the excess output from the tshark extraction.
    hex_stream_text = ''.join(hex_stream_list[6:list_length-2])
    # Convert the hex back to raw bytes.
    file_bytes=binascii.unhexlify(hex_stream_text)
    # Write extracted FTP files.
    fh=open(os.path.join(outdir,'ftp_stream_'+stream_number),'w')
    fh.write(file_bytes)
    fh.close()

def main(args):
  parser = argparse.ArgumentParser()
  parser.add_argument('-o', '--outdir', default='output/')
  parser.add_argument('-i', '--infile')
  parser.add_argument('-D', '--displayfilter', default='')
  args = parser.parse_args()

  if not args.infile:
    parser.error('Missing input file argument.')

  try:
    os.makedirs(vars(args)['outdir'])
  except OSError:
    if not os.path.isdir(vars(args)['outdir']):
      raise

  extract_files(vars(args)['outdir'], vars(args)['infile'], vars(args)['displayfilter'])

if __name__ == "__main__":
  main(sys.argv[1:])
  
########################################################
##
##  
