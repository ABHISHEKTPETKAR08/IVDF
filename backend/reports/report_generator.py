from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
import json
import csv

class ReportGenerator:
    def generate_pdf(self, filename, data):
        os.makedirs("generated_reports", exist_ok=True)

        filepath = f"generated_reports/{filename}.pdf"

        c = canvas.Canvas(filepath, pagesize=letter)
        c.drawString(100, 750, "IVDF Vulnerability Report")

        y = 700
        for key, value in data.items():
            c.drawString(100, y, f"{key}: {value}")
            y -= 20

        c.save()

        return filepath

    def generate_json(self, filename, data):
        os.makedirs("generated_reports", exist_ok=True)

        filepath = f"generated_reports/{filename}.json"

        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)

        return filepath

    def generate_csv(self, filename, data):
        os.makedirs("generated_reports", exist_ok=True)

        filepath = f"generated_reports/{filename}.csv"

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)

            writer.writerow(["Key", "Value"])

            for key, value in data.items():
                writer.writerow([key, value])

        return filepath