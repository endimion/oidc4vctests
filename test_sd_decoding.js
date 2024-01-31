const base64urlDecode = (input) => {
    // Convert base64url to base64 by adding padding characters
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(input.length + (4 - input.length % 4) % 4, '=');
    // Decode base64
    const utf8String = atob(base64);
    // Convert UTF-8 string to byte array
    const bytes = new Uint8Array(utf8String.length);
    for (let i = 0; i < utf8String.length; i++) {
      bytes[i] = utf8String.charCodeAt(i);
    }
    return bytes;
  };
  
  const base64urlEncodedString = "btjhZmc4tOQ6FwUBIgm8DwAZRR_BBhRjz8u5SMGqrkDgxhGAnGc8EA2vqkQWfFGPgJdic_3Blsen0ERqDghw2Q~WyI0eTdrc1dwWl82SFJmc3ROS2YxVWNBIiwiZ2l2ZW5fbmFtZSIsIlNhYmluZSBVbHJpa2UiXQ";
  const decodedBytes = base64urlDecode(base64urlEncodedString);
  const decodedString = new TextDecoder().decode(decodedBytes);
  const decodedArray = JSON.parse(decodedString);
  console.log(decodedArray)
  