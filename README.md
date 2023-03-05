
for more information how it had  been created
https://docs.google.com/document/d/11qMO0QSBqvCJs4bTUgcZA2ZDxr83HAw0rsv6QdRSaeI/edit

Instructions:
1. Install, if you don`t have: Sysmon and python(Internet in help), numpy and pandas(on powershell: pip install numpy,pandasm,lxml)
2. open powershell as admin
3. cd '..\..\Users\vipda\OneDrive\Рабочий стол\'
4. Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 | Export-Clixml sysmon_log50.xml 
	p.s. MaxEvents-it how many logs do u need to check, write files with num how much u have logs

5. open new xml-file (sysmon_log50.xml) and replace 1st string to ' <Objs Version="1.1.0.1"> '
6. python3 .\program_for_anomalies_on_Windows.py
7. Write: sysmon_log50.xml(or another ur file name)
8. Now u have information more about ur pc+dataframe with logs in cute view
9. The end)
