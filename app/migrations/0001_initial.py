# Generated by Django 5.0.2 on 2024-03-28 12:16

import django.contrib.auth.models
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ActiveStatus",
            fields=[
                (
                    "active_status_id",
                    models.AutoField(primary_key=True, serialize=False),
                ),
                ("account_id", models.IntegerField(blank=True, null=True)),
                ("status", models.CharField(max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="Module",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("account_id", models.IntegerField()),
                ("module_name", models.CharField(max_length=255)),
                ("description", models.TextField()),
                ("active_status_id", models.IntegerField(default=1)),
                ("created_by", models.IntegerField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_by", models.IntegerField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name="Role",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("role_id", models.IntegerField()),
                ("role_name", models.CharField(max_length=100)),
                ("description", models.TextField()),
                ("created_by", models.IntegerField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_by", models.IntegerField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name="Permission",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("permission_name", models.CharField(max_length=255)),
                ("description", models.TextField()),
                ("active_status_id", models.IntegerField()),
                ("created_by", models.IntegerField()),
                ("updated_by", models.IntegerField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "module",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="app.module"
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="CustomUser",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "is_active",
                    models.BooleanField(
                        default=True,
                        help_text="Designates whether this user should be treated as active. Unselect this instead of deleting accounts.",
                        verbose_name="active",
                    ),
                ),
                ("email", models.EmailField(max_length=254, unique=True)),
                ("full_name", models.CharField(default="", max_length=255)),
                ("company_name", models.CharField(default="", max_length=255)),
                (
                    "role_name",
                    models.CharField(default=None, max_length=100, null=True),
                ),
                (
                    "profile_path",
                    models.ImageField(blank=True, null=True, upload_to="profile_path/"),
                ),
                (
                    "role",
                    models.ForeignKey(
                        default=None,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="app.role",
                    ),
                ),
            ],
            options={
                "verbose_name": "user",
                "verbose_name_plural": "users",
                "abstract": False,
            },
            managers=[("objects", django.contrib.auth.models.UserManager()),],
        ),
        migrations.CreateModel(
            name="RolePermissions",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("valid_from", models.DateField()),
                ("valid_till", models.DateField()),
                ("created_by", models.IntegerField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_by", models.IntegerField()),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "active_status",
                    models.ForeignKey(
                        default=None,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="app.activestatus",
                    ),
                ),
                (
                    "permission",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="app.permission"
                    ),
                ),
                (
                    "role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="app.role"
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="UserRole",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("account_id", models.IntegerField()),
                ("valid_from", models.DateTimeField()),
                ("valid_till", models.DateTimeField()),
                ("active_status_id", models.IntegerField()),
                ("created_by", models.IntegerField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_by", models.IntegerField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
                (
                    "role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="app.role"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
