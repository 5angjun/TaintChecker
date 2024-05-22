# from https://gist.github.com/sudhackar/0f38d742e451938dfa8e92468c789e8c
from idaapi import *
import idc
import idaapi
import ida_hexrays
import idautils

import sark


from idaapi import *
import idc
import idaapi
import ida_hexrays
import idautils
import ida_lines as il
import shutil, re, os, errno

import ida_hexrays
import ida_idaapi
import ida_kernwin as kw
import ida_lines as il
import ida_diskio
import ida_lines
from idaapi import *
from collections import Counter
GREEN = 0x00FF00
LIGHT_GREEN = 0xCCFFCC
BASIC = 0xffffffff
PLUGIN_NAME = "TaintChecker"

def log(text):
    print(f"[+] TaintChecker : {text}\n")


from idaapi import *
import idc
import idaapi
import ida_hexrays
import idautils
import ida_lines as il
import shutil, re, os, errno

import ida_hexrays
import ida_idaapi
import ida_kernwin as kw
import ida_lines as il
import ida_diskio
import ida_lines
from idaapi import *

import sark
def lex_citem_indexes(line):
    i = 0
    indexes = []
    line_length = len(line)
    while i < line_length:
        if line[i] == idaapi.COLOR_ON:
            i += 1
            if ord(line[i]) == idaapi.COLOR_ADDR:
                i += 1
                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE
                indexes.append(citem_index)
                continue
        i += 1
    return indexes


import ida_hexrays
import idautils
import idaapi
import ida_name
import ida_nalt

a=None
my_list = []
b=None
exploit = None
BASIC = 0xffffffff

analyze_func = {}
result = {}

def same(a,b):
    if a==b:
        return True
    global my_list

    for each_range in my_list:
        min = each_range[0]
        max = each_range[1]

        if a >=min and a <max and b>=min and b <max:
            return True
    return False
# 특정 함수 호출의 인자를 디컴파일된 형태로 찾는 visitor 클래스


def explore(e):
    if e.opname =="var":
        #print(e.get_v().getv().name)
        return e.get_v().getv().name, "var"
    # just string
    elif e.opname =="obj":
        #print("obj",hex(e.obj_ea))
        return (hex(e.obj_ea), "string")
    # reference -> we need to explore it
    elif e.opname =="ref":
        #print("ref")
        return explore(e.x)
    # just static number
    elif e.opname =="num":                        
       # print(hex(e.n._value))
        return (hex(e.n._value), "constant")
    else:
        return explore(e.x)
    

my_test=None

class FuncCallVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self,addr):
        super(FuncCallVisitor, self).__init__(ida_hexrays.CV_FAST)
        self.target_func_name = addr

    def visit_expr(self, e):
        global analyze_func, result
       # print(f"e.ea is {hex(e.ea)}")
        if e.ea==0xffffffff or e.ea ==0xffffffffffffffff:
            return 0
        
        
        if not same(e.ea, self.target_func_name):
            return 0
        #print("DEBUG",hex(e.ea), hex(self.target_func_name))
       # print(f"e.ea is {hex(e.ea)} in 0x000B0460 ~ 0x:000B0480 ")
        if e.op == ida_hexrays.cot_call and e.x.obj_ea != idaapi.BADADDR:
            called_func_ea = e.x.obj_ea
            called_func_name = ida_funcs.get_func_name(called_func_ea)
            #if called_func_name == self.target_func_name:
            #print("AAAAAAAAAAAAAAAAAAAAAAAAAAA")
            if True:
               # print(f"Found call to {called_func_name} at {hex(called_func_ea)} with arguments:")
                global a,b,my_test
                b=e
                a=e.a
                for index in range(e.a.size()):
                    print(f"{hex(e.ea)} {index}th argument is ",end='')
                    # just simple variable
                    argument = explore(e.a[index])
                    #print(type(argument))
                    print(argument)
                    # if index==1:
                    #     print(e.a[index].string)
                    #print(f"argument[1] is {argument[1]} {type(argument[1])}")
                    if argument[1]=="string":
                       # print(f"{argument[1]}==string")
                        string_at_address = idaapi.get_strlit_contents(int(argument[0],16),-1,ida_nalt.STRTYPE_C)
                        if string_at_address == None:
                            result["arg"+str(index+1)]=argument[0]    
                        else:
                            result["arg"+str(index+1)]=string_at_address.decode('utf-8')
                     #   print(f"AAAAAA type is {type(string_at_address)}")
                    else:
                        result["arg"+str(index+1)]=argument[0]

                   # print(dir(e))
                    '''
                    ex)  memset(s, 0, sizeof(s));
                    test_0.v.getv().name
                    test_2.x.v.getv().name
                    Python>test_0.operands
                    {'v': <ida_hexrays.var_ref_t; proxy of <Swig Object of type 'var_ref_t *' at 0x000001B6A1D260F0> >}
                    Python>test_1.operands
                    {'n': <ida_hexrays.cnumber_t; proxy of <Swig Object of type 'cnumber_t *' at 0x000001B6A1D26480> >}
                    Python>test_2.operands
                    {'x': <ida_hexrays.cexpr_t; proxy of <Swig Object of type 'cexpr_t *' at 0x000001B6A1D26630> >}
                    Python>dir(test_0)
                    '''
                    #test.get_v().getv().name
                   # print("A")
                    # # 변환된 인자 표현식을 문자열로 출력
                    # arg_str = ida_hexrays.citem_t.print1(arg)
                    # arg_str = ida_lines.tag_remove(arg_str)
                    #print(f"  Argument: {arg_str}")
                return 0
        if e.op==ida_hexrays.cot_asg:
            global exploit
            exploit = e
            #print(e.x.obj_ea)
            print(f"{hex(e.ea)} return is ",end='')
            ret = explore(e.x)

            result['r0']=ret[0]
            print(f"return value is {exploit.x.v.getv().name}")
           # print("e.op==assign")
        return 0


def range_list(addr):
    '''
    Hexrays코드별로 binary boundaries정보를 my_list에 저장함.
    '''
    global my_list 
    
    # 함수 주소 가져오기
    func_ea = ida_funcs.get_func(addr)
    # 함수 역컴파일
    if func_ea == idaapi.BADADDR:
        print(f"[+] range_list Failed to find function address for {addr}.")
        return
    cfunc = idaapi.decompile(func_ea)
    range_list = list(cfunc.boundaries.values())
    for _ in range_list :my_list.append((_.begin().start_ea,_.begin().end_ea))
   # print(my_list)
    my_list.sort(key=lambda x: x[0])
    # hex_tuple_list = [(hex(number), hex(name)) if isinstance(number, int) else (number, name) for number, name in my_list]

    # print(hex_tuple_list)

def analyze_function_for_call(addr):

    '''
    analyze_function_for_call() -> FuncCallVisitor를 통해서 내가 원하는 addr의 psudocode line에서 return value / args들의 이름을 알아냄.
    '''
    # 함수 이름으로부터 함수 주소 얻기
    #func_ea = ida_name.get_name_ea(idaapi.BADADDR, )
    print(f"[+] analyze_function_for_call {hex(addr)}")
    # try:
    #     func_ea = ida_funcs.get_func(addr)
    # except:
    #     '''
    #     Failed while executing plugin_t.run():
    #     Traceback (most recent call last):
    #     File "C:/Users/softsec/Desktop/IDA Pro 7.7/IDA Pro 7.7/plugins/taintChecker.py", line 1467, in run
    #         Checker.hooker.init_stage()
    #     File "C:/Users/softsec/Desktop/IDA Pro 7.7/IDA Pro 7.7/plugins/taintChecker.py", line 1170, in init_stage
    #         analyze_function_for_call(self.abc[i][0])
    #     File "C:/Users/softsec/Desktop/IDA Pro 7.7/IDA Pro 7.7/plugins/taintChecker.py", line 993, in analyze_function_for_call
    #         range_list(addr)
    #     File "C:/Users/softsec/Desktop/IDA Pro 7.7/IDA Pro 7.7/plugins/taintChecker.py", line 972, in range_list
    #         cfunc = idaapi.decompile(func_ea)
    #     File "C:\Users\softsec\Desktop\IDA Pro 7.7\IDA Pro 7.7\python\3\ida_hexrays.py", line 25842, in decompile
    #         raise RuntimeError('arg 1 of decompile expects either ea_t or cfunc_t argument')
    #     RuntimeError: arg 1 of decompile expects either ea_t or cfunc_t argument     
    #     '''
    #     print(f"[+] analyze_function_for_call except {hex(addr)}")
    #     return
    try:
        func_ea = ida_funcs.get_func(addr)
    except:
        return False
    
    if func_ea == idaapi.BADADDR:
        print(f"Failed to find function address for {addr}.")
        return False
    range_list(addr)
    # 특정 함수 디컴파일
    cfunc = idaapi.decompile(func_ea)
    if cfunc is None:
        print("Failed to decompile function.")
        return False
    
    # visitor 생성 및 적용
    visitor = FuncCallVisitor(addr)
    visitor.apply_to(cfunc.body, None)

    return True
# 분석할 함수의 이름 예시: 'example_function'


def colorize_ret(l, item):

    for decompilate, line_num in l:
        pos = 0
        finded = False
        while True:
            pos = decompilate[line_num].line.find(item, pos)
            if pos < 0:
                break
            print(f"pos is {pos} line_num {line_num} len is {len(decompilate[line_num].line)}")
            if pos+len(item) < len(decompilate[line_num].line) and not decompilate[line_num].line[pos+len(item)].isalnum():
                decompilate[line_num].line = decompilate[line_num].line[:pos] + ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR) + decompilate[line_num].line[pos+len(item):]
                pos += len(ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR))
                finded=True
                print("corrupted")
            else:
                pos += 1
        if finded:
            break
    #pass
# 분석할 함수들을 정리함.



def _lex_citem_indexes(line):
    '''
    _lex_citem_indexes() : 해당 수도 코드 라인에서 중요한 인자 idx들을 담고 있는 citem index를 알아냄.\
    return : index리스트
    '''
    i = 0
    indexes = []
    line_length = len(line)
    while i < line_length:
        if line[i] == idaapi.COLOR_ON:
            i += 1
            if ord(line[i]) == idaapi.COLOR_ADDR:
                i += 1
                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE
                indexes.append(citem_index)
                continue
        i += 1
    return indexes


def _map_line2citem(decompilation_text):
    '''
    수도코드 line별로 citem리스트를 저장함.
    '''
    line2citem = {}
    for line_number in range(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = _lex_citem_indexes(line_text)
    return line2citem

def _map_line2node(cfunc, line2citem):
    line2node = {}
    treeitems = cfunc.treeitems
    for line_number, citem_indexes in line2citem.items():
        nodes = set()
        for index in citem_indexes:
            try:
                item = treeitems[index]
                address = item.ea
            except IndexError as e:
                continue
            if address == 0xffffffffffffffff or address==0xffffffff:
                continue
            node = address
            if not node:
                continue
            nodes.add(node)
        line2node[line_number] = nodes
    return line2node

def find_function_by_addr(addr):
    '''
    find_function_by_addr : 내가 원하는 addr의 수도코드에서 어느 line인지 알아내고 그 line에 해당하는 citem들을 return함.
    '''
    func_ea = ida_funcs.get_func(addr)
    cfunc = idaapi.decompile(func_ea)
    decompilation_text = cfunc.get_pseudocode()
    line2citem = _map_line2citem(decompilation_text)

    # 각 line별 citem의 주소를 가져옴
    line2node = _map_line2node(cfunc, line2citem)
    
    candidate = []
    for line_number, line_nodes in line2node.items():
        # citem주소 하나하나 돌아봄
        is_find_flag = False
        for node_address in line_nodes:
            if is_find_flag: break
            if same(node_address, addr):
                #decompilation_text[line_number].bgcolor = GREEN
              #  print(line2citem[line_number])
                candidate.append((decompilation_text, line_number))
            
                
                break
    return candidate




def read_file():
    import re
    filename = 'C:\\Users\\softsec\\Desktop\\docker-share\\taint.log'  # 읽고자 하는 파일의 이름
    pattern = re.compile(r'0x([a-fA-F0-9]+)\s+([a-zA-Z0-9]+)')
    aaa=[]
    # 파일 열기 및 처리
    with open(filename, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                hex_number = match.group(1)  # 16진수 부분
                word = match.group(2)        # 단어 부분 (r0, arg1 등)
                print(f"Hex: 0x{hex_number}, Word: {word}")
                aaa.append((int(hex_number,16),word))
    return aaa

# # 분석할 함수 주소를 주면 result 딕셔너리에 ret, argument들 이름과 주소들이 담김


# -----------------------------------------------------------------------
# This is from https://github.com/patois/dsync/tree/master #
class idb_hook_t(IDB_Hooks):
    def __init__(self, hooker):
        self.hooker = hooker
        IDB_Hooks.__init__(self)

    # def savebase(self):
    #     self.hooker._reset_all_colors()
    #     return 0

# -----------------------------------------------------------------------
class checker_hooks_t(ida_hexrays.Hexrays_Hooks):
    color_dict = {}
    func_list = {}
    path_list = []
    colorized_pseudocode_instances = []
    checker_on = False
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.idbhook = idb_hook_t(self)
        self.idbhook.hook()

    def init_stage(self):
        # 일단 리스트를 읽어옴
        self._read_log('C:\\Users\\softsec\\Desktop\\docker-share\\path.log')

        # 주소 횟수별로 color를 매김
        self._calc_color()
        # 리스트에 있는 주소와 각각의 함수를 매칭시킴.
        self._get_all_func()
        # 일단 asm을 색깔칠함.
        self._colorize_asm(checker_hooks_t.path_list)

        # 이제 수도코드를 칠함
        self._color()


        self.abc= read_file()
        for i in range(len(self.abc)):

            if not analyze_function_for_call(self.abc[i][0]):
                continue
            candidates = find_function_by_addr(self.abc[i][0])
            colorize_ret(candidates,result[self.abc[i][1]])


        #print(checker_hooks_t.func_list)
        #idaapi.save_database("C:\\Users\\softsec\\Desktop\\docker-share\\ida.idb", idaapi.DBFL_COMP)
      # self.test()
    def test(self):
        log("colorize pseudocode")
        target_addr = 0x000B0470
        func_ea = ida_funcs.get_func(0x000B0470)
        cfunc = checker_hooks_t.func_list[func_ea.start_ea]
        decompilation_text = cfunc.get_pseudocode()

        # 수도코드 각 line별로 item index를 가져옴
        line2citem = self._map_line2citem(decompilation_text)

        # 각 line별 citem의 주소를 가져옴
        line2node = self._map_line2node(cfunc, line2citem)

        lines_painted = 0

        executed_nodes = set(checker_hooks_t.path_list)

        for line_number, line_nodes in line2node.items():
            # citem주소 하나하나 돌아봄
            is_find_flag = False
            for node_address in line_nodes:
                if is_find_flag: break
                # citem주소가 executed된 path와 같은 블록에 있다면 체크함.
                if self._are_addresses_in_same_block(node_address, 0x000B0470):
                    self.colorize_ret(decompilation_text,line_number)
                    #decompilation_text[line_number].bgcolor = GREEN
                    #checker_hooks_t.colorized_pseudocode_instances.append((decompilation_text, line_number))
                    #lines_painted += 1
                    is_find_flag = True
                    break

    def colorize_ret(self, decompilation_text, line_number, **kwargs):
        log('colorize_ret')
        sl = decompilation_text[line_number]
        pos = 0
        item = 'v16'
        while True:
            pos = sl.line.find(item, pos)
            if pos < 0:
                break
            if not sl.line[pos+len(item)].isalnum():
                sl.line = sl.line[:pos] + ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR) + sl.line[pos+len(item):]
                pos += len(ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR))
                log("find color")
            else:
                pos += 1
        #idaapi.refresh_idaview_anyway()
    def refresh_pseudocode(self, vu):
        self._apply_colors()
        for i in range(len(self.abc)):
            analyze_function_for_call(self.abc[i][0])
            candidates = find_function_by_addr(self.abc[i][0])
            colorize_ret(candidates,result[self.abc[i][1]])


        return 0

    def cleanup(self):
        #self._reset_all_colors()
        idaapi.refresh_idaview_anyway()

        if self.idbhook:
            self.idbhook.unhook()
            self.idbhook = None

        return

    def _apply_colors(self):
        for k in self.colorized_pseudocode_instances:
            pseudocode, lineno, color = k
            #pseudocode[lineno].bgcolor = GREEN
            pseudocode[lineno].bgcolor = color

    def _reset_all_colors(self):
        # clean asm block
        for node_in_asm_addr in checker_hooks_t.path_list:
            idaapi.set_item_color(node_in_asm_addr, BASIC)

        # clean pseudocode
        for k in self.colorized_pseudocode_instances:
            pseudocode, lineno = k
            pseudocode[lineno].bgcolor = BASIC

    def _are_addresses_in_same_block(self, address1, address2):
        # for each_range in checker_hooks_t.function_range_dict[key]:
        #     min = each_range[0]
        #     max = each_range[1]
        #     if address1==address2:
        #         True
        #     if address1 >=min and address1 <max and address2>=min and address2 <max:
        #         return True
        # return False
        
        try:
            block1 = sark.CodeBlock(address1)
            block2 = sark.CodeBlock(address2)
            return block1.start_ea == block2.start_ea
        except AttributeError:
            print(f"failure",address1,address2)
            return False
        
    def _read_log(self, filename):
        # 파일을 열고 데이터를 읽어서 리스트에 추가
        with open(filename, 'r') as file:
            for line in file:
                # 16진수 형식의 문자열을 정수로 변환하여 리스트에 추가
                checker_hooks_t.path_list.append(int(line.strip(), 16))

    # def _calc_color(self):
    #     address_counts = Counter(checker_hooks_t.path_list)
    #     min_count = min(address_counts.values())
    #     max_count = max(address_counts.values())
    #     def get_color(count, min_count, max_count):
    #         if count == min_count:
    #             return 0xccffcc  # 최소값은 가장 연한 녹색
    #         elif count == max_count:
    #             return 0x008000  # 최대값은 가장 진한 녹색
    #         else:
    #             # 중간 값은 횟수에 따라 연한 녹색에서 진한 녹색으로 변화
    #             intensity = int(((count - min_count) / (max_count - min_count)) * 255)
    #             return (intensity << 8) | 0x000100
    #     for address, count in address_counts.items():
    #         color = get_color(count, min_count, max_count)
    #         checker_hooks_t.color_dict[address]=color
    #         #print(f"Address {hex(address)}: {count} times, Color: #{hex(color)[2:].zfill(6)}")
    def _calc_color(self):
        address_counts = Counter(self.path_list)
        min_count = min(address_counts.values())
        max_count = max(address_counts.values())

        def get_color(count, min_count, max_count):
            if count == min_count:
                return 0xccffcc  # 최소값은 가장 연한 녹색
            elif count == max_count:
                return 0x008000  # 최대값은 가장 진한 녹색
            else:
                # 중간 값은 횟수에 따라 연한 녹색에서 진한 녹색으로 변화
                # intensity 값 계산 수정
                intensity = int(204 + ((count - min_count) / (max_count - min_count)) * (128 - 204))
                return (intensity << 8) | 0x00FF00 & (intensity << 16)

        for address, count in address_counts.items():
            color = get_color(count, min_count, max_count)
            checker_hooks_t.color_dict[address] = color
            # 주소와 색상 정보 출력을 원할 경우 아래 주석을 해제
            #print(f"Address {hex(address)}: {count} times, Color: #{hex(color)[2:].zfill(6)}")

    def _get_all_func(self):
        for addr in checker_hooks_t.path_list:
            target_func = ida_funcs.get_func(addr)
            if target_func:
                target_cfunc = ida_hexrays.decompile(target_func)
                checker_hooks_t.func_list[target_func.start_ea] = target_cfunc
            else:
                log(f"No function at address: {hex(addr)}")
    # # idaapi.decompile로 하면 decompilation_text[line_number].bgcolor = color 했을 때 수도코드 말고 어셈블리어가 칠해짐
    # cfunc = ida_hexrays.decompile(base)

    def _lex_citem_indexes(self, line):
        '''
        _lex_citem_indexes() : 해당 수도 코드 라인에서 중요한 인자 idx들을 담고 있는 citem index를 알아냄.\
        return : index리스트
        '''
        i = 0
        indexes = []
        line_length = len(line)
        while i < line_length:
            if line[i] == idaapi.COLOR_ON:
                i += 1
                if ord(line[i]) == idaapi.COLOR_ADDR:
                    i += 1
                    citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                    i += idaapi.COLOR_ADDR_SIZE
                    indexes.append(citem_index)
                    continue
            i += 1
        return indexes


    def _map_line2citem(self, decompilation_text):
        '''
        수도코드 line별로 citem리스트를 저장함.
        '''
        line2citem = {}
        for line_number in range(decompilation_text.size()):
            line_text = decompilation_text[line_number].line
            line2citem[line_number] = self._lex_citem_indexes(line_text)
        return line2citem

    def _map_line2node(self, cfunc, line2citem):
        line2node = {}
        treeitems = cfunc.treeitems
        for line_number, citem_indexes in line2citem.items():
            nodes = set()
            for index in citem_indexes:
                try:
                    item = treeitems[index]
                    address = item.ea
                except IndexError as e:
                    continue
                if address == 0xffffffffffffffff or address==0xffffffff:
                    continue
                node = address
                if not node:
                    continue
                nodes.add(node)
            line2node[line_number] = nodes
        return line2node

    def _color(self):
        '''
        func_list : 방문한 함수별로 함수 start addr를 키로 가지고 내용은 cfunc를 가짐.
        
        '''
        log("colorize pseudocode")
        for key in checker_hooks_t.func_list:
            cfunc = checker_hooks_t.func_list[key]
            decompilation_text = cfunc.get_pseudocode()

            # 수도코드 각 line별로 item index를 가져옴
            line2citem = self._map_line2citem(decompilation_text)

            # 각 line별 citem의 주소를 가져옴
            line2node = self._map_line2node(cfunc, line2citem)

            lines_painted = 0

            executed_nodes = set(checker_hooks_t.path_list)

            for line_number, line_nodes in line2node.items():
                # citem주소 하나하나 돌아봄
                is_find_flag = False
                for node_address in line_nodes:
                    if is_find_flag: break
                    # citem주소가 executed된 path와 같은 블록에 있다면 체크함.
                    for executed_address in executed_nodes:
                        if self._are_addresses_in_same_block(node_address, executed_address):
                            #decompilation_text[line_number].bgcolor = GREEN
                            decompilation_text[line_number].bgcolor = checker_hooks_t.color_dict[executed_address]
                            checker_hooks_t.colorized_pseudocode_instances.append((decompilation_text, line_number,checker_hooks_t.color_dict[executed_address]))
                            lines_painted += 1
                            is_find_flag = True
                            break


        idaapi.refresh_idaview_anyway()


    def _colorize_asm(self, target_list):
        '''
        _colorize_asm() : asmebler background들을 칠함.
        
        target_list : log파일에 있는 분석된 addr 정보들

        '''
        log("colorize asm")
        for node_in_asm_addr in target_list:
            #idaapi.set_item_color(node_in_asm_addr, GREEN)
            idaapi.set_item_color(node_in_asm_addr, LIGHT_GREEN)

# -----------------------------------------------------------------------
def is_ida_version(min_ver_required):
    return IDA_SDK_VERSION >= min_ver_required

# -----------------------------------------------------------------------
class Checker(ida_idaapi.plugin_t):
    comment = PLUGIN_NAME
    help = PLUGIN_NAME
    flags = PLUGIN_MOD
    wanted_name = PLUGIN_NAME
    wanted_hotkey = 'Ctrl-Alt-E'
    checker_on = False
    hooker = None
    # Plugin init했을 때
    def init(self):
        required_ver = 730
        # 아이다 버전 체크함.
        if not is_ida_version(required_ver) or not init_hexrays_plugin():
            return PLUGIN_SKIP
        log("init\n\n")

        return PLUGIN_KEEP

    def run(self, arg):
        # hxehook이 없다면 훅을 건다.
        if not Checker.checker_on:
            Checker.hooker = checker_hooks_t()
            Checker.hooker.hook()
            Checker.checker_on = True
            Checker.hooker.init_stage()
            log(PLUGIN_NAME+" Started!!")
        else:
            Checker.hooker.unhook()
            Checker.hooker.cleanup()
            Checker.hooker = None
            Checker.checker_on = False
            log(PLUGIN_NAME+" Stopoped!!")
        return

    def term(self):
        try:
            Checker.unhook()
            Checker.hooker.cleanup()
            Checker.hooker = None
        except:
            pass
        return
# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return Checker()