from django.urls import path

from . import views

urlpatterns = (
    path("", views.RunDiscoveryView.as_view(), name="run"),
    path("runs/", views.RunListView.as_view(), name="run_list"),
    path("runs/<int:pk>/", views.RunDetailView.as_view(), name="run_detail"),
    path("neighbors/", views.NeighborListView.as_view(), name="neighbor_list"),
    path("credentials/", views.CredentialListView.as_view(), name="credential_list"),
    path("credentials/add/", views.CredentialEditView.as_view(), name="credential_add"),
    path(
        "credentials/<int:pk>/edit/",
        views.CredentialEditView.as_view(),
        name="credential_edit",
    ),
    path(
        "credentials/<int:pk>/delete/",
        views.CredentialDeleteView.as_view(),
        name="credential_delete",
    ),
)
