const { initializeApp } = require("firebase/app")
const { getAuth, signInWithEmailAndPassword } = require("firebase/auth")
const { getFirestore, collection, getDocs, setDoc, doc } = require("firebase/firestore")

const email = ""
const password = ""

async function solve() {
    let firebaseConfig = {
      apiKey: "",
      authDomain: "",
      databaseURL: "",
      projectId: "",
      storageBucket: "",
      messagingSenderId: "",
      appId: "",
      measurementId: "",
    };
    
    const app = initializeApp(firebaseConfig)
    const auth = getAuth(app)
    const db = getFirestore(app)
        
auth.onAuthStateChanged(async user => {    
        if (user) {
            // logged in
            const snapshot = await getDocs(collection(db, ""))
    
            snapshot.forEach(key => {
                console.log(key.id, ":", key.data())
            })

            process.exit(0)
        }
    })

    /*const data = {
    }

    auth.onAuthStateChanged(async user => {    
        if (user) {
            // logged in
            const snapshot = await setDoc(doc(db, "", ""),data)
            process.exit(0)
        }
    })*/

    await signInWithEmailAndPassword(auth, email, password)
}

solve()