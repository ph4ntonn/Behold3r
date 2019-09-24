import smtplib
from email.mime.text import MIMEText
from config import *


def send_qq_email(data):
    final_content = ""
    subject = "监控域名信息"
    for domain in data:
        if len(data[domain]) != 0:
            content = "以下是监控信息\n{}:\n".format(domain) + ('\n'.join(data[domain]))
        else:
            content = "{}没有新的子域名出现\n".format(domain)
        final_content += content
    msg = MIMEText(final_content)
    msg['Subject'] = subject
    msg['From'] = qq_sender
    msg['To'] = qq_receiver

    try:
        s = smtplib.SMTP_SSL("smtp.qq.com", 465)
        s.login(qq_sender, qq_authcode)
        s.sendmail(qq_sender, qq_receiver, msg.as_string())
    except smtplib.SMTPException as e:
        print(e)
    finally:
        s.quit()


def send_163_email(data):
    final_content = ""
    subject = "监控域名信息"
    for domain in data:
        if len(data[domain]) != 0:
            content = "以下是监控信息\n{}:\n".format(domain) + ('\n'.join(data[domain]))
        else:
            content = "{}没有新的子域名出现\n".format(domain)
        final_content += content
    msg = MIMEText(final_content)
    msg['Subject'] = subject
    msg['From'] = wy_sender
    msg['To'] = wy_receiver

    try:
        s = smtplib.SMTP('smtp.163.com', 25)
        s.login(wy_sender, wy_authcode)
        s.sendmail(wy_sender, wy_receiver,msg.as_string())
    except smtplib.SMTPException as e:
        print(e)
    finally:
        s.quit()
