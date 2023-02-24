import logging
import os

def dump_to_file(file_name, response):
  try:
    with open(file_name, 'wb') as fd:
      for chunk in response.iter_content(chunk_size=65536):
        fd.write(chunk)
    return True
  except Exception as ex:
    logging.error(ex)


def get_file_size(file_path):
  try:
    return os.stat(file_path).st_size/(1024*1024)
  except Exception as ex:
    logging.error(ex)
