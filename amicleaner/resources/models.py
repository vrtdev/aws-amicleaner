#!/usr/bin/env python
# -*- coding: utf-8 -*-


from builtins import str
from builtins import object


class AMI(object):
    def __init__(self):
        self.id = None
        self.architecture = None
        self.block_device_mappings = []
        self.creation_date = None
        self.hypervisor = None
        self.image_type = None
        self.location = None
        self.name = None
        self.owner_id = None
        self.public = None
        self.root_device_name = None
        self.root_device_type = None
        self.state = None
        self.tags = []
        self.virtualization_type = None
        self.launch_permission_mappings = []

    def __str__(self):
        return str({
            'id': self.id,
            'virtualization_type': self.virtualization_type,
            'creation_date': self.creation_date,
            'launch_permission_mappings': self.launch_permission_mappings,
        })

    @staticmethod
    def object_with_json(json):
        if json is None:
            return None

        o = AMI()
        o.id = json.get('ImageId')
        o.name = json.get('Name')
        o.architecture = json.get('Architecture')
        o.creation_date = json.get('CreationDate')
        o.hypervisor = json.get('Hypervisor')
        o.image_type = json.get('ImageType')
        o.location = json.get('ImageLocation')
        o.owner_id = json.get('OwnerId')
        o.public = json.get('ImageLocation')
        o.root_device_name = json.get('RootDeviceName')
        o.root_device_type = json.get('RootDeviceType')
        o.state = json.get('State')
        o.virtualization_type = json.get('VirtualizationType')

        o.tags = [AWSTag.object_with_json(tag) for tag in json.get('Tags', [])]
        ebs_snapshots = [
            AWSBlockDevice.object_with_json(block_device) for block_device
            in json.get('BlockDeviceMappings', [])
        ]
        o.block_device_mappings = [f for f in ebs_snapshots if f]

        launch_permissions = [
            AWSLaunchPermissions.object_with_json(launch_permission) for launch_permission
            in json.get('LaunchPermissions', [])
        ]
        o.launch_permission_mappings = [f for f in launch_permissions if f]

        return o

    def __repr__(self):
        return '{0}: {1} {2}'.format(self.__class__.__name__,
                                     self.id,
                                     self.creation_date)


class AWSEC2Instance(object):
    def __init__(self):
        self.id = None
        self.name = None
        self.launch_time = None
        self.private_ip_address = None
        self.public_ip_address = None
        self.vpc_id = None
        self.image_id = None
        self.private_dns_name = None
        self.key_name = None
        self.subnet_id = None
        self.instance_type = None
        self.availability_zone = None
        self.asg_name = None
        self.tags = []

    def __str__(self):
        return str({
            'id': self.id,
            'name': self.name,
            'image_id': self.image_id,
            'launch_time': self.launch_time,
        })

    @staticmethod
    def object_with_json(json):
        if json is None:
            return None

        o = AWSEC2Instance()
        o.id = json.get('InstanceId')
        o.name = json.get('PrivateDnsName')
        o.launch_time = json.get('LaunchTime')
        o.private_ip_address = json.get('PrivateIpAddress')
        o.public_ip_address = json.get('PublicIpAddress')
        o.vpc_id = json.get('VpcId')
        o.image_id = json.get('ImageId')
        o.private_dns_name = json.get('PrivateDnsName')
        o.key_name = json.get('KeyName')
        o.subnet_id = json.get('SubnetId')
        o.instance_type = json.get('InstanceType')
        o.availability_zone = json.get('Placement').get('AvailabilityZone')
        o.tags = [AWSTag.object_with_json(tag) for tag in json.get('Tags', [])]

        return o


class AWSBlockDevice(object):
    def __init__(self):
        self.device_name = None
        self.snapshot_id = None
        self.volume_size = None
        self.volume_type = None
        self.encrypted = None

    def __str__(self):
        return str({
            'device_name': self.device_name,
            'snapshot_id': self.snapshot_id,
            'volume_size': self.volume_size,
            'volume_type': self.volume_type,
            'encrypted': self.encrypted,
        })

    @staticmethod
    def object_with_json(json):
        if json is None:
            return None

        ebs = json.get('Ebs')
        if ebs is None:
            return None

        o = AWSBlockDevice()
        o.device_name = json.get('DeviceName')
        o.snapshot_id = ebs.get('SnapshotId')
        o.volume_size = ebs.get('VolumeSize')
        o.volume_type = ebs.get('VolumeType')
        o.encrypted = ebs.get('Encrypted')

        return o


class AWSTag(object):
    def __init__(self):
        self.key = None
        self.value = None

    def __str__(self):
        return str({
            'key': self.key,
            'value': self.value,
        })

    @staticmethod
    def object_with_json(json):
        if json is None:
            return None

        o = AWSTag()
        o.key = json.get('Key')
        o.value = json.get('Value')
        return o

class AWSLaunchPermissions(object):
    def __init__(self):
        self.group = None
        self.user_id = None

    def __str__(self):
        return str({
            'group': self.group,
            'user_id': self.user_id,
        })

    @staticmethod
    def object_with_json(json):
        if json is None:
            return None

        o = AWSLaunchPermissions()
        o.group = json.get('Group')
        o.user_id = json.get('UserId')

        return o