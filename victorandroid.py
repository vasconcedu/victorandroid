#!/usr/bin/python3

"""
Imports
"""
import getopt
import sys
import os
import xml.etree.ElementTree
import time 

"""
Globals
"""
VERSION = 'v0.1 "Rally"'
RELEASE_DATE = 'Mar. 9. 2022'
MANIFEST = ''
ANDROID_XMLNS = '{http://schemas.android.com/apk/res/android}'
MANIFEST_APPLICATION_ATTRIBUTE_CHECKS = {
	# attribute to check: message if unspecified
	'allowBackup': '(default is true)',
	'sharedUserId': '',
	'sharedUserLabel': '',
	'networkSecurityConfig': '',
	'allowClearUserData': '(default is true)',
	'debuggable': '(default is false)',
	'usesCleartextTraffic': '(default is: API level 27 or lower => true; API level 28 or higher => false)',
	'requestLegacyExternalStorage': '(default is false)',
	'allowTaskReparenting': '(default is false)',
	'taskAffinity': '',
	'permission': '(if specified => applies to all of the application\'s components.)'
}
UNSPECIFIED = 'Unspecified'

"""
Terminal color chars class, so that we'll look l33t!!! B-)
"""
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

"""
Logger class
"""
class VictorAndroidLogger:
	def section(self, message):
		print (Colors.OKBLUE + '\n\n[===== {} =====]\n\n'.format(message) + Colors.ENDC)
		return

	def info(self, message):
		print('[+] {}'.format(message))
		return

	def infoNewLine(self, message):
		print('\n[+] {}'.format(message))
		return

	def infoSecondLevel(self, message):
		print('    {}'.format(message))
		return

	def infoThirdLevel(self, message):
		print('      |_ {}'.format(message))
		return

	def infoFourthLevel(self, message):
		print('      |____ {}'.format(message))
		return

	def fail(self, message):
		print(Colors.FAIL + '[-] {}'.format(message) + Colors.ENDC)
		return

	def warning(self, message):
		print(Colors.WARNING + Colors.BOLD + '[!] {}'.format(message) + Colors.ENDC)
		return

	def warningNewLine(self, message):
		print(Colors.WARNING + Colors.BOLD + '\n[!] {}'.format(message) + Colors.ENDC)
		return

	def warningSecondLevel(self, message):
		print(Colors.WARNING + Colors.BOLD + '    {}'.format(message) + Colors.ENDC)
		return

	def warningThirdLevel(self, message):
		print(Colors.WARNING + Colors.BOLD + '      |_ {}'.format(message) + Colors.ENDC)
		return

	def warningFourthLevel(self, message):
		print(Colors.WARNING + Colors.BOLD + '      |____ {}'.format(message) + Colors.ENDC)
		return

	def warningFifthLevel(self, message):
		print(Colors.WARNING + Colors.BOLD + '      |_______ {}'.format(message) + Colors.ENDC)
		return

	def success(self, message):
		print(Colors.OKGREEN + '[+] {}'.format(message) + Colors.ENDC)
		return

"""
Log activities
"""
def logActivities(logger, activities):
	if len(activities) == 0:
		logger.infoSecondLevel('No activities found')
	for activity in activities:
		logger.infoSecondLevel(activity)
		if 'exported' in activities[activity]:
			if activities[activity]['exported'] == 'true':
				logger.warningThirdLevel('exported: ' + activities[activity]['exported'])
			else:
				logger.infoThirdLevel('exported: ' + activities[activity]['exported'])
		if 'enabled' in activities[activity]:
			logger.warningThirdLevel('enabled: ' + activities[activity]['enabled'])
		if 'taskAffinity' in activities[activity]:
			if activities[activity]['taskAffinity'] == 'true':
				logger.warningThirdLevel('taskAffinity: ' + activities[activity]['taskAffinity'])
			else:
				logger.infoThirdLevel('taskAffinity: ' + activities[activity]['taskAffinity'])
		if 'allowTaskReparenting' in activities[activity]:
			if activities[activity]['allowTaskReparenting'] == 'true':
				logger.warningThirdLevel('allowTaskReparenting: ' + activities[activity]['allowTaskReparenting'])
			else:
				logger.infoThirdLevel('allowTaskReparenting: ' + activities[activity]['allowTaskReparenting'])
		if 'permission' in activities[activity]:
			logger.infoThirdLevel('permission: ' + activities[activity]['permission'])
		if 'launchMode' in activities[activity]:
			logger.infoThirdLevel('launchMode: ' + activities[activity]['launchMode'])
		logIntentFilters(logger, activities[activity]['intent-filter'])

"""
Log services
"""
def logServices(logger, services):
	if len(services) == 0:
		logger.infoSecondLevel('No services found')
	for service in services:
		logger.infoSecondLevel(service)
		if 'exported' in services[service]:
			if services[service]['exported'] == 'true':
				logger.warningThirdLevel('exported: ' + services[service]['exported'])	
			else:
				logger.infoThirdLevel('exported: ' + services[service]['exported'])
		if 'permission' in services[service]:
			logger.infoThirdLevel('permission: ' + services[service]['permission'])
		if 'enabled' in services[service]:
			logger.infoThirdLevel('enabled: ' + services[service]['enabled'])
		logIntentFilters(logger, services[service]['intent-filter'])

"""
Log providers
"""
def logProviders(logger, providers):
	if len(providers) == 0:
		logger.infoSecondLevel('No providers found')
	for provider in providers:
		logger.infoSecondLevel(provider)
		if 'exported' in providers[provider]:
			if providers[provider]['exported'] == 'true':
				logger.warningThirdLevel('exported: ' + providers[provider]['exported'])	
			else:
				logger.infoThirdLevel('exported: ' + providers[provider]['exported'])
		if 'permission' in providers[provider]:
			logger.infoThirdLevel('permission: ' + providers[provider]['permission'])
		if 'enabled' in providers[provider]:
			logger.infoThirdLevel('enabled: ' + providers[provider]['enabled'])
		if 'grantUriPermissions' in providers[provider]:
			if providers[provider]['grantUriPermissions'] == 'true':
				logger.warningThirdLevel('grantUriPermissions: ' + providers[provider]['grantUriPermissions'])	
			else:
				logger.infoThirdLevel('grantUriPermissions: ' + providers[provider]['grantUriPermissions'])
		if 'readPermission' in providers[provider]:
			logger.warningThirdLevel('readPermission: ' + providers[provider]['readPermission'])	
		if 'writePermission' in providers[provider]:
			logger.warningThirdLevel('writePermission: ' + providers[provider]['writePermission'])	
		logIntentFilters(logger, providers[provider]['intent-filter'])

"""
Log receivers
"""
def logReceivers(logger, receivers):
	if len(receivers) == 0:
		logger.infoSecondLevel('No receivers found')
	for receiver in receivers:
		logger.infoSecondLevel(receiver)
		if 'exported' in receivers[receiver]:
			if receivers[receiver]['exported'] == 'true':
				logger.warningThirdLevel('exported: ' + receivers[receiver]['exported'])	
			else:
				logger.infoThirdLevel('exported: ' + receivers[receiver]['exported'])
		if 'permission' in receivers[receiver]:
			logger.infoThirdLevel('permission: ' + receivers[receiver]['permission'])
		if 'enabled' in receivers[receiver]:
			logger.infoThirdLevel('enabled: ' + receivers[receiver]['enabled'])
		logIntentFilters(logger, receivers[receiver]['intent-filter'])

"""
Log intent filters
"""
def logIntentFilters(logger, intentFilters):
	for intentFilter in intentFilters:
		logger.warningThirdLevel('intent-filter:')
		logger.warningFourthLevel('action: {}'.format(intentFilter['action']))
		logger.warningFourthLevel('category: {}'.format(intentFilter['category']))
		if intentFilter['data'] != UNSPECIFIED:
			logger.warningFourthLevel('data:')
			for data in intentFilter['data']:
				logger.warningFifthLevel(data)
		else:
			logger.warningFourthLevel('data: ' + intentFilter['data'])

"""
Parse intent filter
"""
def parseIntentFilter(component):

	intentFilter = []

	for componentElement in component:
		if componentElement.tag == 'intent-filter':
			action = UNSPECIFIED
			category = UNSPECIFIED
			data = UNSPECIFIED
			for intentFilterElement in componentElement:
				if intentFilterElement.tag == 'action':
					if action == UNSPECIFIED:
						action = []
					action.append(intentFilterElement.attrib[ANDROID_XMLNS + 'name'])
				elif intentFilterElement.tag == 'category':
					if category == UNSPECIFIED:
						category = []
					category.append(intentFilterElement.attrib[ANDROID_XMLNS + 'name'])
				elif intentFilterElement.tag == 'data':
					if data == UNSPECIFIED:
						data = []
					data = parseData(intentFilterElement, data)
			intentFilter.append({
				'action': action,
				'category': category,
				'data': data
			})
	
	return intentFilter

"""
Parse intent filter data entry
"""
def parseData(intentFilterElement, data):

	scheme = UNSPECIFIED
	host = UNSPECIFIED
	port = UNSPECIFIED
	path = UNSPECIFIED
	pathPattern = UNSPECIFIED
	pathPrefix = UNSPECIFIED
	mimeType = UNSPECIFIED
	
	for dataElement in intentFilterElement.attrib:
		if dataElement == ANDROID_XMLNS + 'scheme':
			scheme = intentFilterElement.attrib[ANDROID_XMLNS + 'scheme']
		elif dataElement == ANDROID_XMLNS + 'host':
			host = intentFilterElement.attrib[ANDROID_XMLNS + 'host']
		elif dataElement == ANDROID_XMLNS + 'port':
			port = intentFilterElement.attrib[ANDROID_XMLNS + 'port']
		elif dataElement == ANDROID_XMLNS + 'path':
			path = intentFilterElement.attrib[ANDROID_XMLNS + 'path']
		elif dataElement == ANDROID_XMLNS + 'pathPattern':
			pathPattern = intentFilterElement.attrib[ANDROID_XMLNS + 'pathPattern']
		elif dataElement == ANDROID_XMLNS + 'pathPrefix':
			pathPrefix = intentFilterElement.attrib[ANDROID_XMLNS + 'pathPrefix']
		elif dataElement == ANDROID_XMLNS + 'mimeType':
			mimeType = intentFilterElement.attrib[ANDROID_XMLNS + 'mimeType']
			
	data.append({
		'scheme': scheme,
		'host': host,
		'port': port,
		'path': path,
		'pathPattern': pathPattern,
		'pathPrefix': pathPrefix,
		'mimeType': mimeType
	})

	return data

"""
Analyze provider (manifest-based)
"""
def analyzeProvider(provider):

	providerInfo = {}

	if ANDROID_XMLNS + 'exported' in provider.attrib:
		providerInfo['exported'] = provider.attrib[ANDROID_XMLNS + 'exported']

	if ANDROID_XMLNS + 'permission' in provider.attrib:
		providerInfo['permission'] = provider.attrib[ANDROID_XMLNS + 'permission']

	if ANDROID_XMLNS + 'enabled' in provider.attrib:
		providerInfo['enabled'] = provider.attrib[ANDROID_XMLNS + 'enabled']

	if ANDROID_XMLNS + 'grantUriPermissions' in provider.attrib:
		providerInfo['grantUriPermissions'] = provider.attrib[ANDROID_XMLNS + 'grantUriPermissions']

	if ANDROID_XMLNS + 'readPermission' in provider.attrib:
		providerInfo['readPermission'] = provider.attrib[ANDROID_XMLNS + 'readPermission']

	if ANDROID_XMLNS + 'writePermission' in provider.attrib:
		providerInfo['writePermission'] = provider.attrib[ANDROID_XMLNS + 'writePermission']

	providerInfo['intent-filter'] = parseIntentFilter(provider)

	return providerInfo

"""
Analyze receiver (manifest-based)
"""
def analyzeReceiver(receiver):

	receiverInfo = {}

	if ANDROID_XMLNS + 'exported' in receiver.attrib:
		receiverInfo['exported'] = receiver.attrib[ANDROID_XMLNS + 'exported']

	if ANDROID_XMLNS + 'permission' in receiver.attrib:
		receiverInfo['permission'] = receiver.attrib[ANDROID_XMLNS + 'permission']

	if ANDROID_XMLNS + 'enabled' in receiver.attrib:
		receiverInfo['enabled'] = receiver.attrib[ANDROID_XMLNS + 'enabled']

	receiverInfo['intent-filter'] = parseIntentFilter(receiver)

	return receiverInfo

"""
Analyze service (manifest-based)
"""
def analyzeService(service):

	serviceInfo = {}

	if ANDROID_XMLNS + 'exported' in service.attrib:
		serviceInfo['exported'] = service.attrib[ANDROID_XMLNS + 'exported']

	if ANDROID_XMLNS + 'permission' in service.attrib:
		serviceInfo['permission'] = service.attrib[ANDROID_XMLNS + 'permission']
	
	if ANDROID_XMLNS + 'enabled' in service.attrib:
		serviceInfo['enabled'] = service.attrib[ANDROID_XMLNS + 'enabled']

	serviceInfo['intent-filter'] = parseIntentFilter(service)

	return serviceInfo

"""
Analyze activity (manifest-based)
"""
def analyzeActivity(activity):

	activityInfo = {}

	if ANDROID_XMLNS + 'exported' in activity.attrib:
		activityInfo['exported'] = activity.attrib[ANDROID_XMLNS + 'exported']

	if ANDROID_XMLNS + 'launchMode' in activity.attrib:
		activityInfo['launchMode'] = activity.attrib[ANDROID_XMLNS + 'launchMode']

	if ANDROID_XMLNS + 'permission' in activity.attrib:
		activityInfo['permission'] = activity.attrib[ANDROID_XMLNS + 'permission']

	if ANDROID_XMLNS + 'taskAffinity' in activity.attrib:
		activityInfo['taskAffinity'] = activity.attrib[ANDROID_XMLNS + 'taskAffinity']

	if ANDROID_XMLNS + 'allowTaskReparenting' in activity.attrib:
		activityInfo['allowTaskReparenting'] = activity.attrib[ANDROID_XMLNS + 'allowTaskReparenting']

	if ANDROID_XMLNS + 'enabled' in activity.attrib:
		activityInfo['enabled'] = activity.attrib[ANDROID_XMLNS + 'enabled']

	activityInfo['intent-filter'] = parseIntentFilter(activity)

	return activityInfo

"""
Analyze manifest
"""
def analyzeManifest(manifest):
	
	manifestRoot = xml.etree.ElementTree.parse(manifest).getroot()
	manifestInfo = {}
	manifestInfo['package'] = manifestRoot.attrib['package']
	manifestInfo['sharedUserId'] = UNSPECIFIED
	if 'sharedUserId' in manifestRoot.attrib:
		manifestInfo['sharedUserId'] = manifestRoot.attrib['sharedUserId']
	manifestInfo['sharedUserLabel'] = UNSPECIFIED
	if 'sharedUserLabel' in manifestRoot.attrib:
		manifestInfo['sharedUserLabel'] = manifestRoot.attrib['sharedUserLabel']
	manifestInfo['uses-permission'] = []
	manifestInfo['permission'] = []
	manifestInfo['application'] = {}

	for rootElement in manifestRoot:
		if rootElement.tag == 'application':

			for attributeCheck in MANIFEST_APPLICATION_ATTRIBUTE_CHECKS:
				if ANDROID_XMLNS + attributeCheck in rootElement.attrib:
					manifestInfo['application'][attributeCheck] = rootElement.attrib[ANDROID_XMLNS + attributeCheck]
					if attributeCheck == 'permission':
						manifestInfo['application'][attributeCheck] = manifestInfo['application'][attributeCheck] + ' ' + MANIFEST_APPLICATION_ATTRIBUTE_CHECKS[attributeCheck]
				else:
					manifestInfo['application'][attributeCheck] = UNSPECIFIED + ' ' + MANIFEST_APPLICATION_ATTRIBUTE_CHECKS[attributeCheck]

			manifestInfo['application']['activity'] = {}
			manifestInfo['application']['service'] = {}
			manifestInfo['application']['receiver'] = {}
			manifestInfo['application']['provider'] = {}
			for component in rootElement:
				if component.tag == 'activity':
					manifestInfo['application']['activity'][component.attrib[ANDROID_XMLNS + 'name']] = analyzeActivity(component)
				elif component.tag == 'service':
					manifestInfo['application']['service'][component.attrib[ANDROID_XMLNS + 'name']] = analyzeService(component)
				elif component.tag == 'receiver':
					manifestInfo['application']['receiver'][component.attrib[ANDROID_XMLNS + 'name']] = analyzeReceiver(component)
				elif component.tag == 'provider':
					manifestInfo['application']['provider'][component.attrib[ANDROID_XMLNS + 'name']] = analyzeProvider(component)
		
		elif rootElement.tag == 'uses-permission':
				
			manifestInfo['uses-permission'].append(rootElement.attrib[ANDROID_XMLNS + 'name'])

		elif rootElement.tag == 'permission':

			protectionLevel = UNSPECIFIED
			if ANDROID_XMLNS + 'protectionLevel' in rootElement.attrib:
				protectionLevel = rootElement.attrib[ANDROID_XMLNS + 'protectionLevel']
			manifestInfo['permission'].append({
				'name': rootElement.attrib[ANDROID_XMLNS + 'name'],
				'protectionLevel': protectionLevel
			})

	return manifestInfo

"""
Manifest summary
"""
def manifestSummary(logger):

	logger.info('Application manifest:')
	logger.infoSecondLevel(MANIFEST)

	manifestInfo = analyzeManifest(MANIFEST)
	for entry in manifestInfo:
		if entry != 'uses-permission' and entry != 'permission':
			if entry != 'application':
				logger.infoThirdLevel(entry + ': ' + manifestInfo[entry])
			else:
				for entry in manifestInfo[entry]:
					if entry not in ['activity', 'service', 'receiver', 'provider']:
						if entry == 'allowBackup' and manifestInfo['application'][entry] == 'true':
							logger.warningThirdLevel(entry + ': ' + manifestInfo['application'][entry])
						elif entry == 'debuggable' and manifestInfo['application'][entry] == 'true':
							logger.warningThirdLevel(entry + ': ' + manifestInfo['application'][entry])
						elif entry == 'usesCleartextTraffic' and manifestInfo['application'][entry] == 'true':
							logger.warningThirdLevel(entry + ': ' + manifestInfo['application'][entry]) 
						elif entry == 'requestLegacyExternalStorage' and manifestInfo['application'][entry] == 'true':
							logger.warningThirdLevel(entry + ': ' + manifestInfo['application'][entry])
						elif entry == 'allowTaskReparenting' and manifestInfo['application'][entry] == 'true':
							logger.warningThirdLevel(entry + ': ' + manifestInfo['application'][entry])
						elif entry == 'taskAffinity' and UNSPECIFIED not in manifestInfo['application'][entry]:
							logger.warningThirdLevel(entry + ': ' + manifestInfo['application'][entry])
						else:
							logger.infoThirdLevel(entry + ': ' + manifestInfo['application'][entry])

	logger.section('Permissions summary')
	
	logger.info('App requests:')
	if len(manifestInfo['uses-permission']) == 0:
		logger.infoSecondLevel('No permission requests found')
	else:
		for permission in manifestInfo['uses-permission']:
			logger.infoSecondLevel(permission)
	
	logger.info('App defines:')
	if len(manifestInfo['permission']) == 0:
		logger.infoSecondLevel('No permission definitions found')
	else:
		for permission in manifestInfo['permission']:
			if permission['protectionLevel'] == UNSPECIFIED:
				logger.warningSecondLevel(permission)
			else:
				logger.infoSecondLevel(permission)

	logger.section('Application components')

	# Log activity analysis 
	logger.info('Activities:')
	logActivities(logger, manifestInfo['application']['activity'])

	# Log service analysis 
	logger.info('Services:')
	logServices(logger, manifestInfo['application']['service'])

	# Log receiver analysis 
	logger.info('Receivers:')
	logReceivers(logger, manifestInfo['application']['receiver'])
	
	# Log provider analysis 
	logger.info('Providers:')
	logProviders(logger, manifestInfo['application']['provider'])

	return

"""
Argument parser
"""
def parseArguments(logger):

	global MANIFEST

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hm:", ["help", "manifest="])
		for opt, arg in opts:
			if opt in ['-h', '--help']:
				logger.success('Parsing succeeded.')
				logger.section('Help menu')
				printHelp()
				exit()
			elif opt in ['-m', "--manifest"]:
				MANIFEST = arg

	except Exception as err:
		logger.fail('Incorrect arguments: {}. Cannot proceed.\n'.format(str(err)))
		exit()

	if MANIFEST == '':
		logger.fail("No manifest specified: MANIFEST == ''")
		exit()

	return

"""
Print help
"""
def printHelp():
	print('VictorAndroid+ {}\n'.format(VERSION))
	print('Basic usage:\n\n\tpython3 tool_victorandroid.py -m|--manifest /path/to/AndroidManifest.xml\n')
	print('Options:\n\n\t-h, --help\t\tPrint help\n\t-m, --manifest m\tPath to Android manifest file m\n')

"""
Print banner 
"""
def printBanner():
	print("""{} _  _  ____  ___  ____  _____  ____    __    _  _  ____  ____  _____  ____  ____     _   
( \\/ )(_  _)/ __)(_  _)(  _  )(  _ \\  /__\\  ( \\( )(  _ \\(  _ \\(  _  )(_  _)(  _ \\  _| |_ 
 \\  /  _)(_( (__   )(   )(_)(  )   / /(__)\\  )  (  )(_) ))   / )(_)(  _)(_  )(_) )(_   _)
  \\/  (____)\\___) (__) (_____)(_)\\_)(__)(__)(_)\\_)(____/(_)\\_)(_____)(____)(____/   |_|  {}

                                    VictorAndroid+ {}, released {}
                                                                          ~ by vasconcedu""".format(Colors.FAIL, Colors.ENDC, VERSION, RELEASE_DATE))
	return

"""
Main function
"""
def __main__():

	startTime = time.time_ns()

	# Print tool banner 
	printBanner()

	# Instantiate logger
	logger = VictorAndroidLogger()

	# Parse command line 
	logger.section('Parsing arguments...')
	parseArguments(logger)
	logger.success('Parsing succeeded.')
	logger.info('Manifest file: {}'.format(MANIFEST))

	# Analysis
	logger.section('Manifest summary')
	manifestSummary(logger)

	# Report 
	finishTime = time.time_ns()
	logger.section('Analysis report')
	logger.success('Analysis completed in {} ms.\n'.format((finishTime - startTime) / 1000000))

__main__()
