# reports/views.py

from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
from datetime import datetime, timedelta
from .utils import ReportGenerator
from .models import GeneratedReport
import json
from clinical_app.models import Patient, Payment, Encounter
from django.db.models import Sum

@login_required
def report_dashboard(request):
    """Main report dashboard"""
    recent_reports = GeneratedReport.objects.all().order_by('-generated_at')[:5]
    
    # Quick stats for dashboard
    total_patients = Patient.objects.count()
    total_encounters = Encounter.objects.count()
    total_revenue = Payment.objects.aggregate(total=Sum('amount_paid'))['total'] or 0
    
    context = {
        'recent_reports': recent_reports,
        'total_patients': total_patients,
        'total_encounters': total_encounters,
        'total_revenue': total_revenue,
    }
    return render(request, 'reports/dashboard.html', context)

@login_required
def generate_report(request, report_type):
    """Generate a specific report"""
    if request.method == 'POST':
        # Get parameters from request
        date_range_preset = request.POST.get('date_preset')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')

        # Handle date presets
        end_date = timezone.now().date()
        if date_range_preset == 'last_7_days':
            start_date = end_date - timedelta(days=7)
        elif date_range_preset == 'last_30_days':
            start_date = end_date - timedelta(days=30)
        elif date_range_preset == 'last_90_days':
            start_date = end_date - timedelta(days=90)
        elif date_range_preset == 'this_month':
            start_date = end_date.replace(day=1)
        elif date_range_preset == 'last_month':
            last_day_of_last_month = end_date.replace(day=1) - timedelta(days=1)
            start_date = last_day_of_last_month.replace(day=1)
            end_date = last_day_of_last_month
        elif date_range_preset == 'custom':
            # Use the manually entered dates if 'custom' is selected
            pass
        else:
            # Fallback to custom dates if no preset is selected
            start_date = start_date
            end_date = end_date

        date_range = {
            'start': start_date,
            'end': end_date
        }
        
        filters = {}
        for key in request.POST:
            if key not in ['start_date', 'end_date', 'csrfmiddlewaretoken', 'date_preset']:
                filters[key] = request.POST.get(key)
        
        # Generate report
        generator = ReportGenerator(report_type, date_range, filters)
        format = request.POST.get('format', 'html')
        
        if format == 'pdf':
            pdf_data = generator.to_pdf()
            response = HttpResponse(pdf_data, content_type='application/pdf')
            filename = f"{report_type}_report_{timezone.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            # Save report record
            GeneratedReport.objects.create(
                title=f"{report_type.capitalize()} Report",
                generated_by=request.user,
                date_range_start=date_range.get('start'),
                date_range_end=date_range.get('end'),
                format='pdf',
                parameters=json.dumps(filters)
            )
            
            return response
        
        else:  # HTML format
            html_report = generator.to_html()
            
            # Save report record
            report = GeneratedReport.objects.create(
                title=f"{report_type.capitalize()} Report",
                generated_by=request.user,
                date_range_start=date_range.get('start'),
                date_range_end=date_range.get('end'),
                format='html',
                parameters=json.dumps(filters)
            )
            
            return render(request, 'reports/report_view.html', {
                'report_content': html_report,
                'report': report
            })
    
    # GET request - show form
    return render(request, 'reports/generate_form.html', {
        'report_type': report_type
    })

@login_required
def report_list(request):
    """List all generated reports"""
    reports = GeneratedReport.objects.all().order_by('-generated_at')
    return render(request, 'reports/report_list.html', {'reports': reports})

@login_required
def view_report(request, report_id):
    """View a specific generated report"""
    report = GeneratedReport.objects.get(id=report_id)
    
    # Regenerate the report content
    generator = ReportGenerator(
        report_type=report.template.name.lower() if report.template else 'patient',
        date_range={
            'start': report.date_range_start,
            'end': report.date_range_end
        },
        filters=json.loads(report.parameters) if report.parameters else {}
    )
    
    html_content = generator.to_html()
    
    return render(request, 'reports/report_view.html', {
        'report_content': html_content,
        'report': report
    })

@login_required
def api_report_data(request, report_type):
    """API endpoint for report data (for AJAX charts)"""
    date_range = {
        'start': request.GET.get('start_date'),
        'end': request.GET.get('end_date')
    }
    
    generator = ReportGenerator(report_type, date_range)
    
    if report_type == 'patient':
        data = generator.generate_patient_report()
    elif report_type == 'financial':
        data = generator.generate_financial_report()
    elif report_type == 'clinical':
        data = generator.generate_clinical_report()
    else:
        data = {}
    
    return JsonResponse(data)