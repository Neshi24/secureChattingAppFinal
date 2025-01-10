import { 
  getFirestore, 
  collection, 
  addDoc, 
  query, 
  onSnapshot, 
  where, 
  doc, 
  updateDoc, 
  arrayUnion, 
  getDocs, 
  getDoc,
  setDoc, 
  deleteDoc
} from "firebase/firestore";
import { decryptMessage, encryptMessage, deriveSharedSecret } from "./ChatEncryption.js";
import { db } from '../../firebaseconfig.js';

// Send a friend request by adding an invitation document
export const sendFriendRequest = async (senderEmail, receiverEmail) => {
  try {
    const invitationRef = collection(db, "invitations");
    await addDoc(invitationRef, {
      senderEmail,
      receiverEmail,
      status: "pending",
    });
    console.log('Friend request sent.');
  } catch (error) {
    console.error("Error sending friend request:", error.message);
  }
};

// Listen for received friend requests for a specific user (receiverEmail)
export const listenToFriendRequests = (receiverEmail, callback) => {
  const q = query(
    collection(db, "invitations"),
    where("receiverEmail", "==", receiverEmail),
    where("status", "==", "pending")
  );

  return onSnapshot(q, (snapshot) => {
    const invitations = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    callback(invitations);
  });
};


export const acceptFriendRequest = async (senderEmail, receiverEmail, invitationId) => {
  try {   
    const receiverFriendsRef = doc(db, "friends", receiverEmail); 
    const receiverDoc = await getDoc(receiverFriendsRef);
    if (receiverDoc.exists()) {      
      await updateDoc(receiverFriendsRef, {
        friends: arrayUnion(senderEmail),
      });
    } else {      
      await setDoc(receiverFriendsRef, {
        friends: [senderEmail], 
      });
    }    
    const senderFriendsRef = doc(db, "friends", senderEmail); 
    const senderDoc = await getDoc(senderFriendsRef);
    if (senderDoc.exists()) {
            await updateDoc(senderFriendsRef, {
        friends: arrayUnion(receiverEmail),
      });
    } else {
      
      await setDoc(senderFriendsRef, {
        friends: [receiverEmail], 
      });
    }    
    const invitationRef = doc(db, "invitations", invitationId);      
    await updateDoc(invitationRef, {
      status: "accepted",
    });
    console.log("Friend request accepted successfully!");
  } catch (error) {
    console.error("Error accepting friend request:", error.message);
  }
};

export const denyFriendRequest = async (invitationId) => {
  try {
    // Get the reference to the invitation document
    const invitationRef = doc(db, "invitations", invitationId);
    
    // Update the status to "denied"
    await updateDoc(invitationRef, {
      status: "denied",
    });

    console.log("Friend request denied successfully!");
  } catch (error) {
    console.error("Error denying friend request:", error.message);
    throw new Error("Failed to deny friend request");
  }
};
// Get friends for a user
export const getFriends = (userEmail, callback) => {
  const userDocRef = doc(db, "friends", userEmail); // Access document by its ID (userEmail)
  
  return onSnapshot(userDocRef, (snapshot) => {
    if (snapshot.exists()) {
      callback(snapshot.data().friends || []);
    } else {
      callback([]); // If the document does not exist, return an empty array
    }
  });
};

// Get messages between two users
export const getMessages = (userEmail, receiverEmail, callback) => {
  // Fetch public key and shared secret as usual
  getPublicKey(receiverEmail).then(publicKey => {
    deriveSharedSecret(publicKey).then(sharedsecret => {
      const q = query(
        collection(db, "messages"),
        where("senderEmail", "in", [userEmail, receiverEmail]),
        where("receiverEmail", "in", [userEmail, receiverEmail])
      );

      // Set up real-time listener
      const unsubscribe = onSnapshot(q, (snapshot) => {
        const fetchedMessages = snapshot.docs
          .map((doc) => {
            const data = doc.data();
            const decryptedMessage = decryptMessage(data.text.ciphertext, data.text.iv, sharedsecret);
            return {
              id: doc.id,
              ...data,
              text: decryptedMessage,
            };
          })
          .sort((a, b) => a.timestamp - b.timestamp);
        
        callback(fetchedMessages);
      });

      // Return the cleanup function to unsubscribe
      return unsubscribe; // This is the cleanup function
    });
  });
};

// Send a message
export const sendMessage = async (message, senderEmail, receiverEmail) => {
  const receiverPublickey = await getPublicKey(receiverEmail);
  const encryptedMessage = await encryptMessage(message, receiverPublickey);
  console.log("Encrypted message:", encryptedMessage);
  const publicKey = localStorage.getItem('publicKey');
  if (message.trim() && receiverEmail.trim()) {
    try {
      await addDoc(collection(db, "messages"), {
        text: encryptedMessage,
        senderEmail,
        receiverEmail,
        publicKey,
        timestamp: new Date(),
      });
    } catch (error) {
      console.error("Error sending message:", error.message);
    }
  } else {
    throw new Error("Message and recipient email cannot be empty.");
  }
};

// Add a friend to the user's friends list
export const addFriend = async (userEmail, newFriendEmail) => {
  if (newFriendEmail.trim()) {
    try {
      const q = query(collection(db, "friends"), where("userEmail", "==", userEmail));
      const snapshot = await getDocs(q);

      if (snapshot.empty) {
        await addDoc(collection(db, "friends"), {
          userEmail,
          friends: [newFriendEmail],
        });
      } else {
        const docId = snapshot.docs[0].id;
        const friendDoc = doc(db, "friends", docId);
        await updateDoc(friendDoc, {
          friends: arrayUnion(newFriendEmail),
        });
      }
    } catch (error) {
      console.error("Error adding friend:", error.message);
    }
  } else {
    throw new Error("Friend email cannot be empty.");
  }
};

export const setPublicKey = async (email, key) => {
  console.log(key)
  try {
    const keyRef = collection(db, "publicKeys");
    await addDoc(keyRef, {
      email,
      key
    });
  } catch (error) {
    throw new Error(`Error setting public key: ${error.message}`);
  }
};

export const getPublicKey = async (email) => {
  try {
    const q = query(collection(db, "publicKeys"), where("email", "==", email));
    const querySnapshot = await getDocs(q);
    const docSnap = querySnapshot.docs[0];

    if (docSnap.exists()) {
      const key = await docSnap.data().key;
      console.log("Public key:", key);
      return key;
    } else {
      return null;
    }

  } catch (error) {
    console.error("Error getting public key:", error.message);
    return null;
  }
};
