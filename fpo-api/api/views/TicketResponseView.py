from datetime import timedelta
from django_filters import rest_framework as filters
from rest_framework import filters as default_filters, generics
from django_filters.rest_framework import DjangoFilterBackend
from api.models import TicketResponse, PreparedPdf
from api.serializers import TicketResponseSerializer
from api.auth import IsActiveAndAdminUser
from django.db import transaction, DatabaseError
from django.db.models.functions import Lower

from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    HttpResponseServerError,
    HttpResponseForbidden
)
from rest_framework.request import Request


class TicketResponseListFilter(filters.FilterSet):
    is_archived = filters.BooleanFilter(
        field_name="archived_by", lookup_expr="isnull", exclude=True
    )
    region = filters.NumberFilter(
        field_name="hearing_location__region_id", lookup_expr="exact"
    )
    created_date = filters.IsoDateTimeFilter(
        field_name="created_date__date", method="filter_date"
    )
    archived_date = filters.IsoDateTimeFilter(
        field_name="archived_date__date", method="filter_date"
    )

    """ Combining filters here, if we have is_archived, we want
        to look in the archived_date or created_date fields.
        If it's not archived, only search the created_date field."""

    def filter_date(self, queryset, field_name, value):
        if not value:
            return queryset
        is_archived = self.data.get("is_archived")
        start = value
        end = value + timedelta(hours=24) - timedelta(seconds=1)
        if is_archived == 'true' and field_name == "archived_date__date":
            return queryset.filter(created_date__range=(start, end)) | queryset.filter(
                archived_date__range=(start, end)
            )
        elif is_archived == 'false' and field_name == "created_date__date":
            return queryset.filter(created_date__range=(start, end))
        else:
            return queryset

    class Meta:
        fields = [
            "region",
            "hearing_attendance",
            "dispute_type",
            "is_archived",
            "ticket_number",
            "hearing_location__name",
            "printed_by__name",
            "created_date__date",
            "archived_date__date",
        ]


class CaseInsensitiveOrderingFilter(default_filters.OrderingFilter):
    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)

        if ordering:
            new_ordering = []
            for field in ordering:
                if 'date' in field:
                    new_ordering.append(field)
                elif field.startswith('-'):
                    new_ordering.append(Lower(field[1:]).desc())
                else:
                    new_ordering.append(Lower(field).asc())
            return queryset.order_by(*new_ordering)

        return queryset


class TicketResponseView(generics.ListAPIView):
    """Used for the admin table, sorting, filtering, ordering. """

    permission_classes = [IsActiveAndAdminUser]
    queryset = TicketResponse.objects.all()
    serializer_class = TicketResponseSerializer
    filter_backends = [
        DjangoFilterBackend,
        default_filters.SearchFilter,
        CaseInsensitiveOrderingFilter
    ]
    filterset_class = TicketResponseListFilter

    search_fields = [
        "first_name",
        "middle_name",
        "last_name",
        "ticket_number",
        "hearing_location__name",
        "archived_by__last_name",
        "archived_by__first_name",
    ]
    ordering_fields = [
        "created_date__date",
        "archived_date",
        "hearing_location__name",
        "ticket_number",
        "last_name",
        "first_name",
        "enforcement_officer",
        "detachment"
    ]

    def delete(self, request: Request, id=None):
        if not request.user.is_superuser:
            return HttpResponseForbidden()
        try:
            ticket_response = TicketResponse.objects.get(id=id)
            prepared_pdf = PreparedPdf.objects.get(
                id=ticket_response.prepared_pdf_id
            )
            with transaction.atomic():
                prepared_pdf.delete()
                ticket_response.delete()

        except (TicketResponse.DoesNotExist, PreparedPdf.DoesNotExist):
            return HttpResponseNotFound()
        except DatabaseError:
            return HttpResponseServerError()

        return HttpResponse("success")

