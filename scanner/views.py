from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Scan
from .serializers import ScanSerializer


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def scan_detail_api_view(request, scan_id):
    scan = get_object_or_404(Scan.objects.prefetch_related("vulnerabilities"), pk=scan_id, user=request.user)
    return Response(ScanSerializer(scan).data)
