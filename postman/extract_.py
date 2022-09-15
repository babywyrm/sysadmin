import json

file = json.load(open('sample2.json', 'r'))

def extract_endpoint_from_collection(file):
	try:
		variables = file.get('variable')
	except:
		pass

	def recursive_scan(file):
		for item in file['item']:
			if item.get('item'):
				recursive_scan(item)
			else:
				# customized this to match your needs
				print(f"{item['request']['method']} {item['request']['url']['raw']}")
	
	# the if comparing the value lenght of the first item
	#  if it's more than 2, it's mean the collection have a sub-folder 
	if len(file['item'][0]) > 2:
		return recursive_scan(file)
	else:
		results = ""
		for folder in file.get('item'):
			results = recursive_scan(folder)
		return results

extract_endpoint_from_collection(file)
				      
# OUTPUT
#
# GET {{baseUrl}}/v1/bla/bla/bla
# GET {{baseUrl}}/v1/bla/bla/bla
# GET {{baseUrl}}/v1/bla/bla/bla

##################################
##
##
