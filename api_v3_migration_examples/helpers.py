import logging

def dump_to_file(file_name, response):
   try:
       with open(file_name, 'wb') as fd:
           for chunk in response.iter_content(chunk_size=65536):
               fd.write(chunk)
       return True
   except Exception as ex:
       logging.error(ex)