from django.urls import path
from . import views


urlpatterns = [
    path('',views.index,name="index"),
    path('home',views.home,name="home"),
    path('user_registration',views.user_registration,name="user_registration"),
    path('login_page',views.login_page,name="login_page"),
    path('register/', views.register, name='register'),
    path('verify_otp',views.verify_otp,name="verify_otp"),
    path('login_view',views.login_view,name="login_view"),
    path('admin',views.admin,name="admin"),
    path('forgot_password',views.forgot_password,name="forgot_password"),
    path('verify_reset_otp/', views.verify_reset_otp, name='verify_reset_otp'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('reported-posts/', views.reported_posts, name='reported_posts'),
    path('profile_update', views.profile_update, name='profile_update'),
    path('create_post/', views.create_post, name='create_post'),
    path('post/<int:post_id>/', views.post_detail, name='post_detail'),
    path('post/<int:post_id>/comment/', views.add_comment, name='add_comment'),
    path('post/<int:post_id>/like/', views.like_post, name='like_post'),
    path('user/<str:username>/posts/', views.user_posts, name='user_posts'),
    path('profile/<str:username>/', views.profile_view, name='profile_view'),
    path('my_profile/<str:username>/', views.my_profile_view, name='my_profile_view'),
    path('search/', views.user_search, name='user_search'),
    path('user_management_view/', views.user_management_view, name='user_management_view'),
    path('user-management/delete/<int:user_id>/', views.delete_user_view, name='delete_user'),
path('like/<int:post_id>/', views.toggle_like, name='toggle_like'),
    path('notifications/',views. notifications, name='notifications'),
    path('logout/', views.custom_logout, name='custom_logout'),
    path('send-friend-request/<int:user_id>/', views.send_friend_request, name='send_friend_request'),
    path('accept-friend-request/<int:request_id>/', views.accept_friend_request, name='accept_friend_request'),
    path('reject-friend-request/<int:request_id>/', views.reject_friend_request, name='reject_friend_request'),
    path('friend-requests/', views.friend_requests_list, name='friend_requests'),
    path('profile/<str:username>/friends/', views.friends_list, name='friends_list'),
    path('settings/privacy/', views.privacy_settings, name='privacy_settings'),
    path('reply/<int:comment_id>/', views.add_reply, name='add_reply'),
     path('conversations/', views.conversation_list, name='conversation_list'),
    path('report/<int:post_id>/', views.report_post, name='report_post'),
    path('conversations/start/<int:user_id>/', views.start_conversation, name='start_conversation'),
    path('send-message/<int:recipient_id>/', views.send_message, name='send_message'),
    # pattern for conversation details
    path('conversations/<int:conversation_id>/', views.conversation_detail, name='conversation_detail'),
    path("post/<int:post_id>/edit/", views.edit_post, name="edit_post"),
    path("post/<int:post_id>/delete/", views.delete_post, name="delete_post"),
]
