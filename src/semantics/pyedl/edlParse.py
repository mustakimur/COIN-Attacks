#!/usr/bin/python3
"""
EDL File Parser
Stores ECALL/OCALL associates inputs to unsafe_input_stat.tmp
Stores ECALL function names to unsafe_ecall_stat.tmp
"""

import sys
import re
import os

CONST_RET_TYPE = 10001
CONST_PARAM_TYPE = 10002
CONST_USER = 10003
CONST_NON_USER = 10004
CONST_STRING = 10005
CONST_NON_STRING = 10006


# erase comments from edl code
def erase_comments(string):
    string = re.sub(re.compile("/\*.*?\*/", re.DOTALL), "", string)
    string = re.sub(re.compile("//.*?\n"), "", string)
    return string


# transform arrays to strings
def trans_array_strings(string):
    lines = ''
    for line in string:
        lines += str(line) + '\n'
    return lines


# construct a single line code
def construct_single_line(string):
    lines = ''

    for s in string:
        if (s == '\n'):
            lines += ' '
        else:
            lines += s

    return lines


# parse function signature to return function name and return type
def parse_func_signature(cline):
    func = ''
    rets = ''
    for c in cline:
        if (c == ' '):
            func = ''
        elif (c == '('):
            break
        else:
            func += c
        rets += c

    rets = ((rets.replace("public", "")).replace(func, "")).replace(
        "[cdecl]", "").strip()

    return func, rets


def process_call(cline):
    param_list = []

    (func, rets) = parse_func_signature(cline)

    params = re.search(r'\((.*?)\)', cline).group(1)
    params += '$'

    flag = True
    tmp = ''
    for param in params:
        if (param == '['):
            tmp += param
            flag = False
        elif (param == ']'):
            tmp += param
            flag = True
        elif (flag and (param == ',' or param == '$')):
            param_list.append(tmp.strip())
            tmp = ''
        else:
            tmp += param

    return (func, param_list, rets)


# process ecalls input params
def process_ecalls(unsafe_ecall_file, unsafe_input_file, tline):
    #separate ecalls
    tmp = ''
    ecall_list = []
    for tl in tline:
        if (tl == ';'):
            ecall_list.append(tmp.lstrip())
            tmp = ''
        else:
            tmp += tl

    # parse ecall
    for ecall in ecall_list:
        (func, params, rets) = process_call(ecall)
        unsafe_ecall_file.write(func + "\n")

        # tuple<input_type, input_kind, input_pos, input_connect, input_is_user, input_is_string>
        input_params = []
        # tuple<output_type, output_pos> [may be used in future]
        output_params = []

        # ecall return is an output
        if (rets != 'void'):
            output_params.append((rets, -1))

        param_pos = 0
        for param in params:
            if (param == 'void'):
                continue

            # identify corelate param of this param
            co_param_pos = -1
            if ('=' in param):
                flag = False
                tmp = ''
                for p in param:
                    if (p == '='):
                        flag = True
                    elif (flag and (p == ',' or p == ']')):
                        break
                    elif (flag):
                        tmp += p

                # look forward for the corelation match
                for pp in params:
                    co_param_pos += 1
                    if (tmp == pp):
                        break

            flag = False
            # 'in' suggests in direction for ecall
            if (('in,' in param) or ('in]' in param)):
                if (('user_check,' in param) or ('user_check]' in param)):
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_USER, CONST_NON_STRING))
                elif (('string,' in param) or ('string]' in param)):
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_NON_USER, CONST_STRING))
                else:
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_NON_USER, CONST_NON_STRING))
                flag = True

            # 'out' suggests out direction for ecall
            if (('out,' in param) or ('out]' in param)):
                output_params.append((param, param_pos))
                flag = True

            # default ecall param direction is in
            if (not flag):
                if (('user_check,' in param) or ('user_check]' in param)):
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_USER, CONST_NON_STRING))
                elif (('string,' in param) or ('string]' in param)):
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_NON_USER, CONST_STRING))
                else:
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_NON_USER, CONST_NON_STRING))

            param_pos += 1

        # write <func_name, number_of_argument, input_kind, input_pos, input_connect, input_is_user, input_is_string>
        for item in input_params:
            unsafe_input_file.write(func + "\t" + str(param_pos) + "\t" +
                                    str(item[1]) + "\t" + str(item[2]) + "\t" +
                                    str(item[3]) + "\t" + str(item[4]) + "\t" +
                                    str(item[5]) + "\n")

    return


# parse ocalls return and input params
def process_ocalls(unsafe_input_file, uline):
    # separate ocalls
    tmp = ''
    ocall_list = []
    for ul in uline:
        if (ul == ';'):
            ocall_list.append(tmp.lstrip())
            tmp = ''
        else:
            tmp += ul

    # parse ocall
    for ocall in ocall_list:
        (func, params, rets) = process_call(ocall)

        # tuple<input_type, input_kind, input_pos, input_connect, input_is_user, input_is_string>
        input_params = []
        # tuple<output_type, output_pos> [may be used in future]
        output_params = []

        # ocall return is an input
        if (rets != 'void'):
            input_params.append((rets, CONST_RET_TYPE, -1, -1, CONST_NON_USER,
                                 CONST_NON_STRING))

        param_pos = 0
        for param in params:
            if (param == 'void'):
                continue

            # identify corelate param of this param
            co_param_pos = -1
            if ('=' in param):
                flag = False
                tmp = ''
                for p in param:
                    if (p == '='):
                        flag = True
                    elif (flag and (p == ',' or p == ']')):
                        break
                    elif (flag):
                        tmp += p
                # look forward for the corelation match
                for pp in params:
                    co_param_pos += 1
                    if (tmp in pp.split(' ')):
                        break

            flag = False
            # 'in' suggests out direction for ocall
            if (('in,' in param) or ('in]' in param)):
                output_params.append((param, param_pos))
                flag = True

            # 'out' suggests in direction for ocall
            if (('out,' in param) or ('out]' in param)):
                if (('user_check,' in param) or ('user_check]' in param)):
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_USER, CONST_NON_STRING))
                elif (('string,' in param) or ('string]' in param)):
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_NON_USER, CONST_STRING))
                else:
                    input_params.append(
                        (param, CONST_PARAM_TYPE, param_pos, co_param_pos,
                         CONST_NON_USER, CONST_NON_STRING))
                flag = True

            # default ocall param direction is out
            if (not flag):
                output_params.append((param, param_pos))

            param_pos += 1

        # write <func_name, number_of_argument, input_kind, input_pos, input_connect, input_is_user, input_is_string>
        for item in input_params:
            unsafe_input_file.write(func + "\t" + str(param_pos) + "\t" +
                                    str(item[1]) + "\t" + str(item[2]) + "\t" +
                                    str(item[3]) + "\t" + str(item[4]) + "\t" +
                                    str(item[5]) + "\n")

    return


# return SGX SDK input path
def get_sgx_sdk_path(path):
    ret_path = os.environ['SGX_SDK'] + "/include/"
    return (ret_path + path)


# return the absulute path
def resolve_path(path):
    ret_path = os.path.abspath(path)
    return ret_path


def rec_edl_parser(edl_file, unsafe_input_file, unsafe_ecall_file):
    with open(edl_file) as rf:
        content = rf.readlines()
        content = [x.strip() for x in content]

        # process file contents to a single line code
        lines = trans_array_strings(content)
        lines = erase_comments(lines)
        lines = construct_single_line(lines)

        # process untrusted blocks
        if (re.search(r'\suntrusted \{(.*?)\}', lines) != None):
            ulines = re.findall(r'\suntrusted \{(.*?)\}', lines)
            for uline in ulines:
                process_ocalls(unsafe_input_file, uline)

        # process trusted blocks
        if (re.search(r'\strusted \{(.*?)\}', lines) != None):
            tlines = re.findall(r'\strusted \{(.*?)\}', lines)
            for tline in tlines:
                process_ecalls(unsafe_ecall_file, unsafe_input_file, tline)

        # process external EDL files
        if (re.search(r'\sfrom \"(.*?)\" import \*', lines) != None):
            flines = re.findall(r'\sfrom \"(.*?)\" import \*', lines)
            for fline in flines:
                # SGX SDK Enclave EDL refers
                if (not "/" in fline):
                    sgxsdk_path = get_sgx_sdk_path(fline)
                    rec_edl_parser(sgxsdk_path, unsafe_input_file,
                                   unsafe_ecall_file)
                # Internal Enclave EDL refers
                else:
                    cwd = os.getcwd()
                    os.chdir(os.path.dirname(sys.argv[1]))
                    custom_path = resolve_path(fline)
                    os.chdir(cwd)
                    rec_edl_parser(custom_path, unsafe_input_file,
                                   unsafe_ecall_file)


def main():
    if (len(sys.argv) < 2):
        print('usage: python edlParse.py [EDL_file]')
        sys.exit()
    if os.environ.get('SGX_SDK') is None:
        print('warning: SGX_SDK environment variable not set.')
        sys.exit()

    edl_file = sys.argv[1]
    unsafe_input_file = open("unsafe_input_stat.tmp", "w")
    unsafe_ecall_file = open("unsafe_ecall_stat.tmp", "w")

    # recursively parse EDL files
    rec_edl_parser(edl_file, unsafe_input_file, unsafe_ecall_file)

    unsafe_input_file.close()
    unsafe_ecall_file.close()


if __name__ == "__main__":
    main()