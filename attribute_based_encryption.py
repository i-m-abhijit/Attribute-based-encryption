from charm.charm.toolbox.node import BinNode, OpType
from charm.charm.toolbox.pairinggroup import PairingGroup
from charm.charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07


class User:
    def __init__(self, id, role, category, private_key=None):
        self.id = id
        self.role = role
        self.category = category
        self.private_key = private_key

    def decrypt_data(self, cpabe, pk, ct):
        decrypted_data = cpabe.decrypt(pk, self.private_key, ct) if self.private_key else None
        return decrypted_data if decrypted_data else "Access denied."


class Patient:
    def __init__(self, id, data):
        self.id = id
        self.data = data
        self.group = PairingGroup('SS512')
        self.cpabe = CPabe_BSW07(self.group)
        self.pk, self.mk = self.cpabe.setup()
        self.encrypted_data = None

    def encrypt_data(self, policy):
        self.encrypted_data = self.cpabe.encrypt(self.pk, self.data, policy)

    def generate_key(self, attributes):
        return self.cpabe.keygen(self.pk, self.mk, attributes)


class UserPatientMapping:
    def __init__(self):
        self.mapping = {}

    def add_mapping(self, user, patient):
        if user not in self.mapping:
            self.mapping[user] = set()
        self.mapping[user].add(patient)


class AccessPolicyTree:
    def __init__(self):
        self.root = BinNode(OpType.OR)

    def add_policy(self, user, patient):
        user_id_node = BinNode(f"id_{user.id}")
        user_role_node = BinNode(f"role_{user.role}")
        user_category_node = BinNode(f"category_{user.category}")
        patient_id_node = BinNode(f"patient_id_{patient.id}")

        and_node = BinNode(OpType.AND)
        and_node.addSubNode(user_id_node, user_role_node)
        and_node.addSubNode(and_node, user_category_node)
        and_node.addSubNode(and_node, patient_id_node)

        self.root.addSubNode(self.root, and_node)

    def __str__(self):
        return str(self.root)


class AccessControlSystem:
    def __init__(self, user_patient_mapping):
        self.user_patient_mapping = user_patient_mapping
        self.access_policy_tree = AccessPolicyTree()

    def setup(self):
        for user, patients in self.user_patient_mapping.mapping.items():
            for patient in patients:
                self.access_policy_tree.add_policy(user, patient)
                patient.encrypt_data(str(self.access_policy_tree))
                user.private_key = patient.generate_key([f'id:{user.id}', f'role:{user.role}', f'category:{user.category}'])

    def test_access(self, user, patient):
        decrypted_data = user.decrypt_data(patient.cpabe, patient.pk, patient.encrypted_data)
        print(decrypted_data)


# Create some users, patients and user-patient mappings
patient1 = Patient(1, "This is some sensitive data of patient1")
patient2 = Patient(2, "This is some sensitive data of patient2")
doctor1 = User(1, "doctor", "cardiologist")
doctor2 = User(2, "doctor", "neurologist")
nurse1 = User(3, "nurse", "senior nurse")
nurse2 = User(4, "nurse", "junior nurse")
user_patient_mapping = UserPatientMapping()

# Mapping for patient1
user_patient_mapping.add_mapping(doctor1, patient1)
user_patient_mapping.add_mapping(nurse1, patient1)
user_patient_mapping.add_mapping(doctor2, patient1)

# Mapping for patient2
user_patient_mapping.add_mapping(doctor2, patient2)
user_patient_mapping.add_mapping(nurse2, patient2)

# Initialize the access control system and setup
acs = AccessControlSystem(user_patient_mapping)
acs.setup()

# Test access
acs.test_access(nurse1, patient2)
