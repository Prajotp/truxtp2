from django.urls import path
from .views import register_user, user_login, user_logout
from app import views
from .views import CustomUserListCreate, CustomUserRetrieveUpdateDestroy


urlpatterns = [
    path('add_module/', views.add_module),
    path('fetch_all_modules/', views.fetch_all_modules),
    path('fetch_single_module/', views.fetch_single_module),
    path('update_module/', views.update_module),
    path('delete_module/', views.delete_module),
    path('register/', register_user, name='register'),
    path('login/', user_login, name='login'),
    path('logout/', user_logout, name='logout'),
    path('add_role/', views.add_role),
    path('fetch_roles_dropdown/', views.fetch_roles_dropdown),
    path('fetch_single_role/<int:role_id>/', views.fetch_single_role),
    path('update_role/<int:role_id>/', views.update_role),
    path('delete_role/<int:role_id>/', views.delete_role),
    path('users/', CustomUserListCreate.as_view(), name='user-list-create'),
    path('users/<int:pk>/', CustomUserRetrieveUpdateDestroy.as_view(), name='user-detail'),
    path('assign-role/', views.AssignRoleToUser.as_view()),
    path('fetch-all-user-roles/', views.FetchAllUserRoles.as_view()),
    path('fetch-assigned-role-to-single-user/', views.FetchAssignedRoleToSingleUser.as_view()),
    path('update-assigned-role/', views.UpdateAssignedRole.as_view()),
    path('delete-assigned-role/', views.DeleteAssignedRole.as_view()),
    path('add_permission/', views.add_permission),
    path('fetch_all_permissions/', views.fetch_all_permissions),
    path('fetch_all_permissions_per_account/', views.fetch_all_permissions_per_account),
    path('fetch_permissions_per_module/',views.fetch_permissions_per_module),
    path('fetch_single_permission/', views.fetch_single_permission),
    path('update_permission/', views.update_permission),
    path('delete_permission/', views.delete_permission),
    path('assign-permissions-to-role/', views.assign_permissions_to_role),
    path('fetch-all-role-permissions/', views.fetch_all_role_permissions),
]