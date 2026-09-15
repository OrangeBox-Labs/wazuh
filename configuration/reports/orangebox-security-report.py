#!/usr/bin/env python3
"""Compatibility wrapper for the OrangeBox Wazuh Security Activity Report.

Allows --email to be specified multiple times while keeping one generated
report and one SMTP message addressed to all recipients.
"""
import importlib.util
import re
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

CORE_PATH = "/var/ossec/reports/orangebox-security-report-core.py"


def load_core():
    spec = importlib.util.spec_from_file_location("orangebox_security_report_core", CORE_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"No se pudo cargar {CORE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract_recipients(argv):
    remaining = []
    recipients = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--email":
            if index + 1 >= len(argv):
                raise SystemExit("--email requiere una dirección de correo")
            recipients.append(argv[index + 1])
            index += 2
            continue
        remaining.append(argument)
        index += 1
    if not recipients:
        raise SystemExit("Debe especificar al menos un --email")
    for recipient in recipients:
        if not re.fullmatch(r"[^\\s@]+@[^\\s@]+", recipient):
            raise SystemExit(f"Dirección de correo inválida: {recipient}")
    return remaining, recipients


def main():
    remaining, recipients = extract_recipients(sys.argv[1:])
    core = load_core()

    def send_email(subject, body, _recipient):
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"Wazuh SOC <{core.DEFAULT_FROM}>"
        message["To"] = ", ".join(recipients)
        message.attach(MIMEText("OrangeBox Wazuh Security Activity Report.", "plain", "utf-8"))
        message.attach(MIMEText(body, "html", "utf-8"))
        with smtplib.SMTP(core.SMTP_HOST, core.SMTP_PORT, timeout=30) as smtp:
            smtp.sendmail(core.DEFAULT_FROM, recipients, message.as_string())

    core.send_email = send_email
    sys.argv = [CORE_PATH] + remaining + ["--email", recipients[0]]
    core.main()
    print(f"Destinatarios: {', '.join(recipients)}")


if __name__ == "__main__":
    main()
