from django.db import models
from clinical_app.models import User

class ReportTemplate(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    model_name = models.CharField(max_length=100, help_text="Target model for this report")
    template_file = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name

class GeneratedReport(models.Model):
    REPORT_FORMAT_CHOICES = [
        ('pdf', 'PDF'),
        ('html', 'HTML'),
        ('csv', 'CSV'),
        ('excel', 'Excel'),
    ]
    
    title = models.CharField(max_length=255)
    template = models.ForeignKey(ReportTemplate, on_delete=models.SET_NULL, null=True, blank=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    date_range_start = models.DateField(null=True, blank=True)
    date_range_end = models.DateField(null=True, blank=True)
    format = models.CharField(max_length=10, choices=REPORT_FORMAT_CHOICES, default='pdf')
    file_path = models.CharField(max_length=500, blank=True, null=True)
    parameters = models.JSONField(default=dict, blank=True)
    is_scheduled = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.title} - {self.generated_at.strftime('%Y-%m-%d')}"