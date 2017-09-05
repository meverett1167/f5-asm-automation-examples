
import pprint
import requests
from f5.bigip import ManagementRoot
from icontrol.exceptions import iControlUnexpectedHTTPError
import json
import argparse

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

pp = pprint.PrettyPrinter()


class AsmAutomator(object):
    def __init__(self, username, password, host):

        self.mgmt_url = "https://%s" %(host)
        self.mgmt = ManagementRoot(host, username, password)
        self.tmos_version = self.mgmt._meta_data['tmos_version']
        self.s = self.mgmt._meta_data['bigip']._meta_data['icr_session']
        self.base_asm_url = "{}{}".format(self.mgmt._meta_data['uri'], "tm/asm")

    @classmethod
    def get_partition(cls, policy_name):
        ''' returns to tuple of partition name and policy name '''
        parts = policy_name.split('/')
        pol_par = ('/'.join(parts[1:-1]), parts[-1])
        return pol_par


    def _get_version(self):
        return mgmt.tmos_version


    def _post(self, url, payload, verify= False):
        self.s.post(url, data=json.dumps(payload))


    def _get(self, url, **kwargs):
        params = kwargs
        r = self.s.get(url, params=json.dumps(params), verify=False)
        return self.s.get(url, params=json.dumps(params), verify=False)

    def _delete(self, url, **kwargs):

        # Looks like a bug in F5 Python SDK calling delete, deletes the object but reports error
        #r = self.s.delete(url, params=kwargs, verify=False)
        #return self.s.delete(url, params=kwargs, verify=False)

        # Calling requests library directly, should remove once installed fixed code
        response = requests.delete(url, params=kwargs, auth=requests.auth.HTTPBasicAuth('admin', '@mike5651'), verify=False)
        return response.text


    def get_all_policy_ids(self, **kwargs):
        '''returns list of all policies, by the policy id, can be passed a filter '''

        requests_params = kwargs # havent done anything with this yet

        req_url = "{}/policies".format(self.base_asm_url)
        try:
            icr_response = self._get(req_url, **requests_params)
            pol_ids = []
            for pol in icr_response.json()['items']:
                pol_ids.append(pol['id'])

            return pol_ids

        except iControlUnexpectedHTTPError, e:
            return None


    def get_policy_id(self,name):
        ''' takes a policy name and finds the policy id.  OData filters for name seem to have issues with
            certain characters, so getting all ids's then filter names
        '''

        # Some names need to be enclosed in single quotes for filter to work properly
        pol_name = "'{}'".format(name)

        requests_params = {
            '$filter': "name eq {}".format(pol_name)
        }


        req_url = "{}/policies".format(self.base_asm_url)

        try:
            icr_response = self._get(req_url, **requests_params)

            #need to handle better, but this to see if the filter failed
            policy_id = None
            for item in icr_response.json()['items']:
                if item['name'] == name:
                    policy_id = item['id']

            return policy_id

        except iControlUnexpectedHTTPError, e:
            return None


    def get_policyname_from_id(self, policy_id):
        ''' return list of all ASM policy names on instance '''

        requests_params = {
            '$select': 'name'
        }

        req_url = "{}/policies/{}".format(self.base_asm_url,policy_id)

        try:
            icr_response = self._get(req_url,**requests_params)
            policy_name = icr_response.json()['name']

            return policy_name

        except iControlUnexpectedHTTPError, e:
            return None




    def get_enabled_policy_signatures_by_id_and_ref(self, policy_id):
        ''' Returns list of all policy signatures that are enabled by their ID and reference '''

        request_params = {

            '$filter': 'enabled eq true',
            '$select': 'id, signatureReference'
        }

        req_url = "{}/policies/{}/signatures".format(self.base_asm_url, policy_id)

        try:
            icr_response = self._get(req_url, **request_params)
            sig_idrefs = []
            for item in icr_response.json()['items']:
                sig_ref = {'id': item['id'], 'signatureReference': item['signatureReference']['link']}
                sig_idrefs.append(sig_ref)

            return sig_idrefs

        except iControlUnexpectedHTTPError, e:
            return None


    def get_signature_detail(self, pol_sig_idref):
        ''' returns dict of signature details '''

        # get the sigID from the signature reference
        ref = pol_sig_idref['signatureReference']
        ref = ref.split('signatures/')
        ref = ref[1].split('?')
        ref = ref[0]

        req_url = "{}/signatures/{}".format(self.base_asm_url, ref)

        try:
            icr_response = self._get(req_url)
            sig_details = icr_response.json()
            return sig_details

        except iControlUnexpectedHTTPError, e:
            return None


    def print_details(self, policy_id):
        ''' print to std out for now '''

        print "Policy Name {}:".format(self.get_policyname_from_id(policy_id))
        sig_idrefs = self.get_enabled_policy_signatures_by_id_and_ref(policy_id)
        print "Total Enabled Signatures on Policy: {}".format(len(sig_idrefs))
        for sig_ref in sig_idrefs:
            sig_details = self.get_signature_detail(sig_ref)
            print " -------------------- Signature Details ---------------------------"
            print " Signature Name: {}".format(sig_details['name'])
            print " Signature ID: {}".format(sig_details['id'])
            print " Signature Description: \n {}:".format(sig_details['description'])
            print " -------------------- End of Signature Details ---------------------\n"


if __name__ == '__main__':

    usage = "Usage: %prog [options]"
    parser = argparse.ArgumentParser(usage)
    parser.add_argument('-p', '--policy_name',
                        help="Name of the policy you want to check",
                        dest='policy_name')
    parser.add_argument('-a', '--all_pols', dest='all_pols',
                        action= 'store_true', help="If set, script will run through all policies on ASM")

    options = parser.parse_args()

    all_pols = False
    if options.policy_name is None and not options.all_pols:
        print "Please provide name of a policy to check, or select \"-a\" to check all policies"
        parser.print_help()
        exit(-1)


    elif options.all_pols and options.policy_name is None:
        all_pols = options.all_pols

    elif options.all_pols and options.policy_name is not None:
        all_pols = options.all_pols

    else:
        policy_name = options.policy_name

    # bigip creds
    bigip = '192.168.15.162'
    user = 'USER'
    passw = 'PASS'

    myAsm = AsmAutomator(user, passw, bigip)
    if (all_pols):
        pols = myAsm.get_all_policy_ids()
        for pol in pols:
            myAsm.print_details(pol)
    else:
        policy_id = myAsm.get_policy_id(policy_name)
        print policy_name
        print policy_id
        if policy_id is not None:
            myAsm.print_details(policy_id)
        else:
            print "Please enter a valid policy name, or check all policies "
            exit(-1)







