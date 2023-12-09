from django.db import models

# Create your models here.
from django.db.models import CASCADE


class ClientRegister_Model(models.Model):
    username = models.CharField(max_length=30)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=10)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    gender= models.CharField(max_length=30)
    address= models.CharField(max_length=30)


class predict_attack_type(models.Model):


    RID= models.CharField(max_length=300)
    ip_src= models.CharField(max_length=300)
    ip_dst= models.CharField(max_length=300)
    tcp_srcport= models.CharField(max_length=300)
    tcp_dstport= models.CharField(max_length=300)
    tcp_flags_push= models.CharField(max_length=300)
    tcp_flags_ack= models.CharField(max_length=300)
    tcp_ack= models.CharField(max_length=300)
    frame_time= models.CharField(max_length=300)
    packets_bytes= models.CharField(max_length=300)
    tx_packets= models.CharField(max_length=300)
    tx_bytes= models.CharField(max_length=300)
    rx_packets= models.CharField(max_length=300)
    rx_bytes= models.CharField(max_length=300)
    Prediction= models.CharField(max_length=300)

class detection_accuracy(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class detection_ratio(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)



