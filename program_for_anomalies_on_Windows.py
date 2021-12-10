
a=input('Введите название файла: ')
name_of_a_file=a

import numpy as np
import pandas as pd
from lxml import etree as et



#делаем так, чтобы сразу заменялась первая строка
'''
def replace_line(f_in,f_out):   
    fin = open(f_in, "r")
    fout = open(f_out, "w")
    
    for line in fin:
        print(line)
        fout.write(line.replace('xmlns',''))
    fin.close()
    fout.close()
replace_line('sysmon_log2.xml','2.xml')
'''


def xml_to_df_all_my_version(xmlfile):

  #сюды пиши нужные для тебя форматы логов
  Index = []
  MachineName = []
  Task = []
  Level = []
  Message = []
  RecordId = []
  ProcessId = []
  ThreadId = []
  TimeCreated = []
  events_S = []
  events_G = []
  Opcode = []
  Keywords = []
  ProviderId = []
  ProviderName = []
  Id = []
  Version = []
  Qualifiers = []
  LogName = []
  TimeCreated=[]
  BinaryLength = []
  Value = []
  AccountDomainSid = []
  root = et.parse(xmlfile).getroot()
  
  root.tag='Objs'
  for index, childs in enumerate(root):
    Index.append(index)
    #print(index ,childs.tag,'\n')
    #тут лог разбиты по одному(и выведены их номера через принт выше), в следующем ифе они начнут обрабатываться
    event_S=[]
    event_G=[]
    k=0
    for childre in childs:
      if childre.tag == 'MS':
        for i in childre:
          if i.tag == 'S' and i.attrib['N'] == 'Message':
              Message.append(i.text)
              k+=1
    if k==0:
      Message.append('пустота')

    for index, child in enumerate(childs):

      #print('1 ',child.tag)
      # тут теги: TN, ToString, Props, MS


      if child.tag == "Props":

        #print('prps: ',child.tag)
        #тут у прупса рассмотрим теги внутри него
          #print( i.tag, end=',')
          # ТУТ ЭТИ ВАШИ I32,By,Nil,By,I32,I16,I64,I64,S,G,S,I32,I32,S,S ...

          #как записывать 1 тег в датафрейм этот ваш
          k=0
          for i in child:
            if i.tag == 'S' and i.attrib['N'] == 'MachineName':
              #print(i.tag,i.attrib,)
              MachineName.append(i.text)
              k+=1
          if k==0:
            MachineName.append('пустота1')#тут должна быть пустота датафрейма np.none вроде

          #вот как все должно реализовываться в этом примере
          k=0
          for i in child:
            if i.tag == 'I32' and i.attrib['N'] == 'ProcessId':
              #print(i.tag,i.attrib,)
              ProcessId.append(i.text)
              k+=1
          if k==0:
            ProcessId.append('пустота1')  

            #реализации Ромы
          for i in child:
            if i.tag == 'I32' and i.attrib['N'] == 'ThreadId':
              #print(i.tag,i.attrib,)
              ThreadId.append(i.text)
              k+=1
          if k==0:
            ThreadId.append('пустота1')
          for i in child:
            if i.tag == 'S' and i.attrib['N'] == 'LogName':
              #print(i.tag,i.attrib,)
              LogName.append(i.text)
              k+=1
          if k==0:
            LogName.append('пустота1')
          for i in child:
            if i.tag == 'G' and i.attrib['N'] == 'ProviderId':
              #print(i.tag,i.attrib,)
              ProviderId.append(i.text)
              k+=1
          if k==0:
            ProviderId.append('пустота1')
          for i in child:
            if i.tag == 'S' and i.attrib['N'] == 'ProviderName':
              #print(i.tag,i.attrib,)
              ProviderName.append(i.text)
              k+=1
          if k==0:
            ProviderName.append('пустота1')
          for i in child:
            if i.tag == 'I64' and i.attrib['N'] == 'RecordId':
              #print(i.tag,i.attrib,)
              RecordId.append(i.text)
              k+=1
          if k==0:
            RecordId.append('пустота1')
          for i in child:
            if i.tag == 'I64' and i.attrib['N'] == 'Keywords':
              #print(i.tag,i.attrib,)
              Keywords.append(i.text)
              k+=1
          if k==0:
            Keywords.append('пустота1')
          for i in child:
            if i.tag == 'I16' and i.attrib['N'] == 'Opcode':
              #print(i.tag,i.attrib,)
              Opcode.append(i.text)
              k+=1
          if k==0:
            Opcode.append('пустота1')
          for i in child:
            if i.tag == 'I32' and i.attrib['N'] == 'Task':
              #print(i.tag,i.attrib,)
              Task.append(i.text)
              k+=1
          if k==0:
            Task.append('пустота1')
          for i in child:
            if i.tag == 'By' and i.attrib['N'] == 'Level':
              #print(i.tag,i.attrib,)
              Level.append(i.text)
              k+=1
          if k==0:
            Level.append('пустота1')
          for i in child:
            if i.tag == 'Nil' and i.attrib['N'] == 'Qualifiers':
              #print(i.tag,i.attrib,)
              Qualifiers.append(i.text)
              k+=1
          if k==0:
            Qualifiers.append('пустота1')#пишет нан в массив, то есть аттрибут есть, а текст пустой
          for i in child:
            if i.tag == 'By' and i.attrib['N'] == 'Version':
              #print(i.tag,i.attrib,)
              Version.append(i.text)
              k+=1
          if k==0:
            Version.append('пустота1')
          for i in child:
            if i.tag =='I32' and i.attrib['N'] == 'Id':
              #print(i.tag,i.attrib,)
              Id.append(i.text)
              k+=1
          if k==0:
            Id.append('пустота1')

          for i in child:
            if i.tag =='DT' and i.attrib['N'] == 'TimeCreated':
              #print(i.tag,i.attrib,)
              TimeCreated.append(i.text)
              k+=1
          if k==0:
            TimeCreated.append('пустота1')
          
          if i.tag == 'Obj' and i.attrib['N'] == 'Properties':
                        # <Obj N="Properties" RefId="5"> - надо найти это поле и достать оттуда все данные
                        # obj = []
                        for j in i:
                            # дальше гам нужен только тэг <LST>
                            # obj.append
                            # print(j.tag)
                            if j.tag == 'LST':
                                for k in j:
                                    # тут много тэгов obj, надо взять только последний
                                    # print(k.tag)
                                    if k.tag == 'Obj':
                                        for n in k:
                                            # в каждом obj нам нужен props
                                            # <Props>
                                            #     <S N="Value">C:\Windows\System32\svchost.exe</S>
                                            # </Props>
                                            if n.tag == 'Props':
                                                for s in n:
                                                    if s.tag == 'S' and s.attrib['N'] == 'Value':
                                                        # <S N="Value"> - тут он только отсюда текст берет и записывает в события
                                                        # print(s.text)
                                                        event_S.append(s.text)
                                                    if s.tag == 'G' and s.attrib['N'] == 'Value':
                                                        event_G.append(s.text)





          for childone23 in child:
            if childone23.tag=='Obj' and childone23.attrib['N']=='UserId':
              for child1two3 in childone23:
                if child1two3.tag=='Props':

                  k=0  
                  for child12three in child1two3:
                    if child12three.tag =='I32' and child12three.attrib['N'] == 'BinaryLength':
                      #I32 N="BinaryLength
                      BinaryLength.append(child12three.text)
                      k+=1
                  if k==0:
                      BinaryLength.append('пустота1')
                  k=0  
                  for child12three in child1two3:
                    if child12three.tag =='Nil' and child12three.attrib['N'] == 'AccountDomainSid':
                      #I32 N="BinaryLength
                      AccountDomainSid.append(child12three.text)
                      k+=1
                  if k==0:
                      AccountDomainSid.append('пустота1')
                  k=0  
                  for child12three in child1two3:
                    if child12three.tag =='S' and child12three.attrib['N'] == 'Value':
                      #I32 N="BinaryLength
                      Value.append(child12three.text)
                      k+=1
                  if k==0:
                      Value.append('пустота1')


    events_S.append(event_S)
    events_G.append(event_G)
          
          




  #print(Index,  MachineName,  Task,   Level,  Message,  RecordId,  ProcessId,ThreadId, TimeCreated,events_S , events_G)
  #print(Id,Version,Qualifiers,Opcode )
  #print(Keywords)
  #print(ProviderName)
  #print(ProviderId)
  #print(LogName)
  #print('закончиличь пропсы')
  #print(BinaryLength)
  #print(AccountDomainSid)
  #print(Value)
  #print(events_S)
  #print(events_G)
  #print(Message)

# for i in Message,events_G,events_S,Value,AccountDomainSid,BinaryLength,LogName,ProviderId,ProviderName,Keywords,\
#          Id,Version,Qualifiers,Opcode,Index,  MachineName,  Task,  Level,  RecordId,  ProcessId,ThreadId, TimeCreated :
#     print(len(i))
  #ВСЕ РАБОТАЕТ!!11!)
  
  #РАЗБИЕНИЕ МЕССАДЖ НА РАЗНЫЕ ВЕЩИ


  #print(Message[2])

  for i in range(len(Message)):
      Message[i]=Message[i].split('_x000D__x000A_')
  #print(Message[2])

  Processterminated = []
  RuleName = []
  UtcTime = []
  ProcessGuid = []
  ProcessId = []
  Image = []
  User = []
  ProcessCreate = []
  FileVersion = []
  Description = []
  Product = []
  Company = []
  OriginalFileName = []
  CommandLine = []
  CurrentDirectory = []
  LogonGuid = []
  LogonId = []
  TerminalSessionId = []
  IntegrityLevel = []
  Hashes = []
  ParentProcessGuid = []
  ParentProcessId = []
  ParentImage = []
  ParentCommandLine = []
  ParentUser = []


  from collections import defaultdict

  res = defaultdict(list)

  for x in Message:
    aaa = {x: 'пустота 1' for x in ['Process terminated', 'RuleName', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User', 'Process Create', 'FileVersion', 'Description', 'Product', 'Company', 'OriginalFileName', 'CommandLine', 'CurrentDirectory', 'LogonGuid', 'LogonId', 'TerminalSessionId', 'IntegrityLevel', 'Hashes', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'ParentCommandLine', 'ParentUser']}

    for y in x:
      name, val = y.split(':', 1)[0],y.split(':', 1)[1]
      aaa[name] = val.strip()
    for name, val in aaa.items():
      res[name].append(val)

  #print({x: len(y) for x,y in res.items()})
  
  for name, arr in res.items():
    name = name.replace(' ', '')
    for x in arr:
      locals()[name].append(x)

  a=dict(res)    
  UtcTime = a.get('UtcTime')
  ProcessGuid =a.get('ProcessGuid')
  ProcessId =a.get('ProcessId')
  Image =a.get('Image')
  User =a.get('User')
  ProcessCreate =a.get('ProcessCreate')
  FileVersion =a.get('FileVersion')
  Description =a.get('Description')
  Product =a.get('Product')
  Company =a.get('Company')
  OriginalFileName =a.get('OriginalFileName')
  CommandLine =a.get('CommandLine')
  CurrentDirectory =a.get('CurrentDirectory')
  LogonGuid =a.get('LogonGuid')
  LogonId =a.get('LogonId')
  TerminalSessionId =a.get('TerminalSessionId')
  IntegrityLevel =a.get('IntegrityLevel')
  Hashes =a.get('Hashes')
  ParentProcessGuid =a.get('ParentProcessGuid')
  ParentProcessId =a.get('ParentProcessId')
  ParentImage =a.get('ParentImage')
  ParentCommandLine =a.get('ParentCommandLine')
  ParentUser =a.get('ParentUser')

  #print(ParentProcessId)

  df = pd.DataFrame({'Index':Index,'Value':Value, 'EventID': Id,'AccountDomainSid':AccountDomainSid,'BinaryLength':BinaryLength,'LogName':LogName,
                     'ProviderId':ProviderId,'ProviderName':ProviderName,'Keywords':Keywords,'Version':Version,'Qualifiers':Qualifiers,'Opcode':Opcode,
                     'Level': Level, 'Task': Task,
                       'RecordId': RecordId, 'ProcessId': ProcessId, 'ThreadId': ThreadId,
                       'TimeCreated': TimeCreated, 'MachineName': MachineName,'ParentProcessId':ParentProcessId, 'Message': Message,
                     'UtcTime':UtcTime, 'ProcessGuid':ProcessGuid,  'Image':Image, 'User':User, 'ProcessCreate':ProcessCreate, 
                     'FileVersion':FileVersion, 'Description':Description, 'Product':Product, 'Company':Company, 'OriginalFileName':OriginalFileName,
                     'CommandLine':CommandLine, 'CurrentDirectory':CurrentDirectory, 'LogonGuid':LogonGuid, 'LogonId':LogonId, 'TerminalSessionId':TerminalSessionId,
                     'IntegrityLevel':IntegrityLevel, 'Hashes':Hashes, 'ParentProcessGuid':ParentProcessGuid, 'ParentImage':ParentImage, 
                     'ParentCommandLine':ParentCommandLine, 'ParentUser':ParentUser, 
                       'events_S': pd.Series(events_S), 'events_G': pd.Series(events_G)}) 

  df = df.astype({'EventID': np.int64})
  df = df.astype({'ProcessId': np.int64})

  return df 

def otrabotka_logov(sorted_df):

  k=0
  a0=sorted_df[sorted_df['EventID'] == 1 ]#не понял кто время изменил, щас порешаем с ним раз на раз 

  print('Проверьте лучше файлы следующие лучше, так как они изменили время создания файла')
  a0s=a0["Image"].unique()
  for i in a0s:
    k+=1
    print(i)
  if k==0:
    print('повезло, ничего нет')

  a1=sorted_df[sorted_df['EventID'] == 12 ] 
  a2=sorted_df[sorted_df['EventID'] == 13] # логи об изменении регистра
  a3=sorted_df[sorted_df['EventID'] == 14 ] 
  untraditional_lgbtqplus_nonbinary_helicopter=pd.concat([a1,a2,a3], ignore_index=True) 
  uniq=untraditional_lgbtqplus_nonbinary_helicopter["Image"].unique()
  print('Проверьте лучше файлы следующие лучше, так как они изменили регистр')
  k=0
  for i in uniq:
    k+=1
    print(i)
  if k==0:
    print('повезло, ничего нет')

  untraditional_lgbtqplus_nonbinary_helicopter
  a4=sorted_df[sorted_df['EventID'] == 23 ] # удалил файл какой-то
  a5=sorted_df[sorted_df['EventID'] == 26 ] 
  untraditional_lgbtqplus_nonbinary_helicopter=pd.concat([a4,a5], ignore_index=True) 
  uniq=untraditional_lgbtqplus_nonbinary_helicopter["Image"].unique()
  print('Проверьте лучше файлы следующие лучше, так как они удалили какие-то файлы')
  k=0
  for i in uniq:
    k+=1
    print(i)
  if k==0:
    print('повезло, ничего нет')

  print('Вот программы, которые позарились на cmd:')
  a6=sorted_df[sorted_df['Image'].isin(['C:\\Windows\\System32\\cmd.exe'])]#а вот те, что юзали cmd зачем-то
  a7=a6[a6['EventID'] == 1 ]#так как есть открытие и закрытие, теперь смотрит на тех, кто только открыл командную строку
  a7 = a7.astype({'ParentProcessId': np.int64})
  parents=list(a7['ParentProcessId'].unique())#idродителей, подставляем потом и ищем в 
  a8=df1[df1['ProcessId'].isin(parents)]
  uniq=a8["Image"].unique()
  k=0
  for i in uniq:
    k+=1
    print(i)
  if k==0:
    print('повезло, ничего нет')



#сделаем эту фигню
df1=xml_to_df_all_my_version(name_of_a_file)#перевод из xml в в датафрейм
#засейвим отработанный лог
df1.to_csv('вот отработали 2000 логов.csv')# ЗДЕСЬ ПИШИ КОЛ-ВО ОТРАБОТАННЫХ ЛОГОВ, ЧТОБЫ НЕ ЗАБЫТЬ

#а вот и началась работа программы
otrabotka_logov(df1)
