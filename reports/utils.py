import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64
from django.db.models import Count, Sum, Avg, Q
from django.utils import timezone
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.offline import plot
import pdfkit
from clinical_app.models import Patient, Payment, Encounter, Billing

class ReportGenerator:
    def __init__(self, report_type, date_range=None, filters=None):
        self.report_type = report_type
        self.date_range = date_range or {}
        self.filters = filters or {}
        self.data = None
        self.charts = []
        
    def generate_patient_report(self):
        """Generate comprehensive patient report"""
        patients = Patient.objects.all()
        
        # Apply filters
        if self.filters.get('gender'):
            patients = patients.filter(gender=self.filters['gender'])
        
        if self.date_range.get('start') and self.date_range.get('end'):
            start_date = self.date_range['start']
            end_date = self.date_range['end']
            patients = patients.filter(registration_date__range=[start_date, end_date])
        
        # Prepare data for visualization
        patient_data = list(patients.values(
            'patient_id', 'first_name', 'last_name', 'gender', 
            'registration_date', 'has_insurance'
        ))
        
        # Generate charts
        self._generate_patient_charts(patients)
        
        return {
            'data': patient_data,
            'total_count': patients.count(),
            'charts': self.charts,
            'summary': self._generate_patient_summary(patients)
        }
    
    def generate_financial_report(self):
        """Generate financial report"""
        bills = Billing.objects.all()
        payments = Payment.objects.all()
        
        # Apply date filters
        if self.date_range.get('start') and self.date_range.get('end'):
            start_date = self.date_range['start']
            end_date = self.date_range['end']
            bills = bills.filter(created_at__range=[start_date, end_date])
            payments = payments.filter(paid_on__range=[start_date, end_date])
        
        # Calculate metrics
        total_revenue = payments.aggregate(total=Sum('amount_paid'))['total'] or 0
        total_billed = bills.aggregate(total=Sum('amount'))['total'] or 0
        outstanding = total_billed - total_revenue
        
        # Payment method breakdown
        payment_methods = payments.values('method').annotate(
            total=Sum('amount_paid'), count=Count('id')
        )
        
        # Generate charts
        self._generate_financial_charts(payments, bills)
        
        return {
            'total_revenue': total_revenue,
            'total_billed': total_billed,
            'outstanding': outstanding,
            'payment_methods': list(payment_methods),
            'charts': self.charts
        }
    
    def generate_clinical_report(self):
        """Generate clinical activity report"""
        encounters = Encounter.objects.all()
        
        if self.date_range.get('start') and self.date_range.get('end'):
            start_date = self.date_range['start']
            end_date = self.date_range['end']
            encounters = encounters.filter(encounter_date__range=[start_date, end_date])
        
        # Encounter type breakdown
        encounter_types = encounters.values('encounter_type').annotate(
            count=Count('id')
        )
        
        # Doctor activity
        doctor_activity = encounters.values('doctor__user__first_name', 'doctor__user__last_name').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Generate charts
        self._generate_clinical_charts(encounters)
        
        return {
            'total_encounters': encounters.count(),
            'encounter_types': list(encounter_types),
            'top_doctors': list(doctor_activity),
            'charts': self.charts
        }
    
    def _generate_patient_charts(self, patients):
        """Generate patient-related charts"""
        # Gender distribution
        gender_data = patients.values('gender').annotate(count=Count('id'))
        fig = px.pie(gender_data, values='count', names='gender', 
                    title='Patient Gender Distribution')
        self.charts.append(plot(fig, output_type='div', include_plotlyjs=False))
        
        # Registration trend
        reg_data = patients.extra(
            select={'day': 'date(registration_date)'}
        ).values('day').annotate(count=Count('id')).order_by('day')
        
        if reg_data:
            fig = px.line(reg_data, x='day', y='count', 
                         title='Patient Registration Trend')
            self.charts.append(plot(fig, output_type='div', include_plotlyjs=False))
    
    def _generate_financial_charts(self, payments, bills):
        """Generate financial charts"""
        # Revenue by day
        revenue_data = payments.extra(
            select={'day': 'date(paid_on)'}
        ).values('day').annotate(total=Sum('amount_paid')).order_by('day')
        
        if revenue_data:
            fig = px.line(revenue_data, x='day', y='total', 
                         title='Daily Revenue')
            self.charts.append(plot(fig, output_type='div', include_plotlyjs=False))
        
        # Payment method distribution
        method_data = payments.values('method').annotate(total=Sum('amount_paid'))
        fig = px.pie(method_data, values='total', names='method',
                    title='Payment Method Distribution')
        self.charts.append(plot(fig, output_type='div', include_plotlyjs=False))
    
    def _generate_clinical_charts(self, encounters):
        """Generate clinical charts"""
        # Encounters by type
        type_data = encounters.values('encounter_type').annotate(count=Count('id'))
        fig = px.bar(type_data, x='encounter_type', y='count',
                    title='Encounters by Type')
        self.charts.append(plot(fig, output_type='div', include_plotlyjs=False))
        
        # Encounters by day
        daily_data = encounters.extra(
            select={'day': 'date(encounter_date)'}
        ).values('day').annotate(count=Count('id')).order_by('day')
        
        if daily_data:
            fig = px.line(daily_data, x='day', y='count',
                         title='Daily Encounters')
            self.charts.append(plot(fig, output_type='div', include_plotlyjs=False))
    
    def _generate_patient_summary(self, patients):
        """Generate patient summary statistics"""
        insurance_count = patients.filter(has_insurance=True).count()
        cash_count = patients.count() - insurance_count
        
        return {
            'total_patients': patients.count(),
            'insurance_patients': insurance_count,
            'cash_patients': cash_count,
            'new_this_week': patients.filter(
                registration_date__gte=timezone.now() - timedelta(days=7)
            ).count()
        }
    
    def to_html(self):
        """Generate HTML report"""
        if self.report_type == 'patient':
            data = self.generate_patient_report()
        elif self.report_type == 'financial':
            data = self.generate_financial_report()
        elif self.report_type == 'clinical':
            data = self.generate_clinical_report()
        else:
            data = {}
        
        # Render HTML template with data
        from django.template.loader import render_to_string
        return render_to_string(f'reports/{self.report_type}_report.html', {
            'data': data,
            'report_type': self.report_type,
            'date_range': self.date_range,
            'generated_at': timezone.now()
        })
    
    def to_pdf(self):
        """Generate PDF report"""
        html = self.to_html()
        return pdfkit.from_string(html, False)