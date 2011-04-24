#pragma once
#include <windows.h>
#define STACK_SIZE 32 //2^32 entries.
template<class T, int stack_size>
class MyStack
{
public:
	MyStack(): index(0) {}
	void push_back(const T& e)
	{
		if (index<stack_size)
		s[index++]=e;
	}
	void pop_back()
	{
		index--;
	}
	T& back()
	{
		return s[index-1];
	}
	int size() {return index;}
private:
	int index;
	T s[stack_size];
};

template <class T, class D>
class TreeNode
{
public:
	TreeNode():key(0),data(),Left(0),Right(0),rank(1),factor(0) {}
	TreeNode(char* k, const D& d):data(d),Left(0),Right(0),rank(1),factor(0) 
	{
		int l=strlen(k);
		key=new char[l+1];
		strcpy(key,k);
	}
	~TreeNode() {if (key) delete key;}
	TreeNode *Left,*Right;
	unsigned int rank;
	char factor;
	char* key;
	D data;
};
template<class T,class D>
class NodePath
{
public:
	NodePath(TreeNode<T,D> *n=0,char f=0):Node(n),factor(f) {}
	TreeNode<T,D> *Node;
	char factor;
};
template <class D>
class AVLTree
{
public:
	AVLTree() {}
	~AVLTree()
	{
		while (head.Left)
			DeleteRoot();
	}
	TreeNode<char*,D>* TreeRoot() const {return head.Left;}
	TreeNode<char*,D>* Insert(char* key, const D& data)
	{
		if (head.Left)
		{
			MyStack<TreeNode<char*,D>*,STACK_SIZE> path; 
			TreeNode<char*,D> *DownNode,*ParentNode,*BalanceNode,*TryNode,*NewNode; //P,T,S,Q
			ParentNode=&head;
			path.push_back(ParentNode);
			char factor,f;
			int cmp_result;
			BalanceNode=DownNode=head.Left;
			for(;;) //The first part of AVL tree insert. Just do as binary tree insert routine and record some nodes.
			{
				cmp_result=strcmp(key,DownNode->key);
				if (cmp_result==0) return DownNode; //Duplicate key. Return and do nothing.
				factor = cmp_result<0?-1:1;
				//factor = _FactorCompare(key, DownNode->key);
				TryNode = _FactorLink(DownNode,factor);
				if (factor==-1) path.push_back(DownNode);
				if (TryNode) //DownNode has a child.
				{
					if (TryNode->factor!=0) //Keep track of unbalance node and its parent.
					{
						ParentNode=DownNode;
						BalanceNode=TryNode;
					}	
					DownNode=TryNode;
					
				}
				else break; //Finished binary tree search;
			}
			while(path.size())
			{
				path.back()->rank++;
				path.pop_back();
			}
			TryNode=new TreeNode<char*,D>(key,data);
			_FactorLink(DownNode,factor) = TryNode;
			NewNode=TryNode;
			//Finished binary tree insert. Next to do is modify balance factors between 
			//BalanceNode and the new node.
			TreeNode<char*,D>* ModifyNode;
			cmp_result=strcmp(key,BalanceNode->key);
			factor=cmp_result<0 ? factor=-1:1;
			//factor=key<BalanceNode->key ? factor=-1:1; //Determine the balance factor at BalanceNode.
			ModifyNode=DownNode=_FactorLink(BalanceNode,factor); 
			//ModifyNode will be the 1st child.
			//DownNode will travel from here to the recent inserted node (TryNode).
			while(DownNode!=TryNode) //Check if we reach the bottom.
			{
				f=strcmp(key,DownNode->key)<0?-1:1;
				//f=_FactorCompare(key,DownNode->key);
				DownNode->factor=f;
				DownNode = _FactorLink(DownNode,f);//Modify balance factor and travels down.
			}
			//Finshed modifying balance factor.
			//Next to do is check the tree if it's unbalance and recover balance.
			if (BalanceNode->factor==0)  //Tree has grown higher. 
			{
				BalanceNode->factor=factor;
				_IncreaseHeight(); //Modify balance factor and increase the height.
				return NewNode;
			}
			if (BalanceNode->factor+factor==0) //Tree has gotten more balanced.
			{
				BalanceNode->factor=0; //Set balance factor to 0.
				return NewNode;
			}
			//Tree has gotten out of balance.
			if (ModifyNode->factor==factor) //A node and it child has same factor. Single rotation.
				DownNode=_SingleRotation(BalanceNode,ModifyNode,factor);	
			else //A node and its child has converse factor. Double rotation.
				DownNode = _DoubleRotation(BalanceNode, ModifyNode, factor);
			//Finished the balance working. Set child to the root of the new child tree.
			if (BalanceNode==ParentNode->Left) ParentNode->Left=DownNode;
			else ParentNode->Right=DownNode;
			return NewNode;
		}
		else //root null?
		{
			head.Left=new TreeNode<char*,D>(key,data);
			head.rank++;
			_IncreaseHeight();
			return head.Left;
		}
	}

	bool Delete(char* key)
	{
		NodePath<char*,D> PathNode;
		MyStack<NodePath<char*,D>,STACK_SIZE> path; //Use to record a path to the destination node.
		path.push_back(NodePath<char*,D>(&head,-1));
		TreeNode<char*,D> *TryNode,*ChildNode,*BalanceNode,*SuccNode; 
		TryNode=head.Left;
		char factor;
		int cmp_result;
		while (1) //Search for the 
		{
			if (TryNode==0) return false; //Not found.
			cmp_result=strcmp(key,TryNode->key);
			if (cmp_result==0) break; //Key found, continue to delete.
			factor = cmp_result<0? -1:1;
			//factor = _FactorCompare( key, TryNode->key );
			path.push_back(NodePath<char*,D>(TryNode,factor));
			TryNode=_FactorLink(TryNode,factor); //Move to left.
		}
		SuccNode=TryNode->Right; //Find a successor.
		factor=1;
		if (SuccNode==0)
		{
			SuccNode=TryNode->Left; //Find a successor.
			factor=-1;
		}
		path.push_back(NodePath<char*,D>(TryNode,factor));
		while (SuccNode)
		{
			path.push_back(NodePath<char*,D>(SuccNode,-factor));
			SuccNode=_FactorLink(SuccNode,-factor);
			//SuccNode=SuccNode->Left;
		}
		PathNode=path.back();
		delete TryNode->key;
		TryNode->key=PathNode.Node->key;
		PathNode.Node->key=0; //Replace key and data field with the successor.
		TryNode->data=PathNode.Node->data;
		path.pop_back();
		_FactorLink(path.back().Node,path.back().factor) = _FactorLink(PathNode.Node,-PathNode.factor); 
		delete PathNode.Node; //Remove the successor from the tree and release memory.
		PathNode=path.back();
		while (1) //Rebalance the tree along the path back to the root.
		{
			if (path.size()==1)
			{
				_DecreaseHeight(); break;
			}
			BalanceNode=PathNode.Node;
			if (BalanceNode->factor==0) 
				//A balance node, just need to adjust the factor. Don't have to recurve since subtree height stays.
			{
				BalanceNode->factor=-PathNode.factor;
				break;
			}
			if (BalanceNode->factor==PathNode.factor) //Node get more balance. Subtree height decrease, need to recurve.
			{
				BalanceNode->factor=0;
				path.pop_back();
				PathNode=path.back();
				continue;
			}
			//Node get out of balance. Here raises 3 cases.
			ChildNode = _FactorLink(BalanceNode, -PathNode.factor);
			if (ChildNode->factor == 0) //New case different to insert operation.
			{
				TryNode = _SingleRotation2( BalanceNode, ChildNode, BalanceNode->factor );
				path.pop_back();
				PathNode=path.back();
				_FactorLink(PathNode.Node, PathNode.factor) = TryNode;
				break;
			}
			else
			{
				if ( ChildNode->factor == BalanceNode->factor ) //Analogous to insert operation case 1.
					TryNode = _SingleRotation( BalanceNode, ChildNode, BalanceNode->factor );
				else if ( ChildNode->factor + BalanceNode->factor == 0 ) //Analogous to insert operation case 2.
					TryNode = _DoubleRotation( BalanceNode, ChildNode, BalanceNode->factor );
			}
			path.pop_back(); //Recurve back along the path.
			PathNode=path.back();
			_FactorLink(PathNode.Node, PathNode.factor) = TryNode;
		}
		return true;
	}
	D& operator [] (char* key)
	{
		return (Insert(key,D())->data);
	}
	TreeNode<char*,D>* Search(char* key)
	{
		TreeNode<char*,D>* Find=head.Left;
		int cmp_result;
		while (Find)
		{
			cmp_result=strcmp(key,Find->key);
			if (cmp_result==0) break;
			cmp_result=cmp_result<0?-1:1;
			Find = _FactorLink(Find, cmp_result);
		}
		return Find;
	}
	unsigned int Height() const {return (unsigned int)(head.Right);}
	unsigned int Count() const {return head.rank;}
private:
	bool DeleteRoot()
	{
		NodePath<char*,D> PathNode;
		MyStack<NodePath<char*,D>,STACK_SIZE> path; //Use to record a path to the destination node.
		path.push_back(NodePath<char*,D>(&head,-1));
		TreeNode<char*,D> *TryNode,*ChildNode,*BalanceNode,*SuccNode; 
		TryNode=head.Left;
		char factor;
		SuccNode=TryNode->Right; //Find a successor.
		factor=1;
		if (SuccNode==0)
		{
			SuccNode=TryNode->Left; //Find a successor.
			factor=-1;
		}
		path.push_back(NodePath<char*,D>(TryNode,factor));
		while (SuccNode)
		{
			path.push_back(NodePath<char*,D>(SuccNode,-factor));
			SuccNode=_FactorLink(SuccNode,-factor);
			//SuccNode=SuccNode->Left;
		}
		PathNode=path.back();
		delete TryNode->key;
		TryNode->key=PathNode.Node->key;
		PathNode.Node->key=0; //Replace key and data field with the successor.
		TryNode->data=PathNode.Node->data;
		path.pop_back();
		_FactorLink(path.back().Node,path.back().factor) = _FactorLink(PathNode.Node,-PathNode.factor); 
		//delete PathNode.Node->key;
		__assume (PathNode.Node->key==0);
		delete PathNode.Node; //Remove the successor from the tree and release memory.
		PathNode=path.back();
		while (1) //Rebalance the tree along the path back to the root.
		{
			if (path.size()==1)
			{
				_DecreaseHeight(); break;
			}
			BalanceNode=PathNode.Node;
			if (BalanceNode->factor==0) 
				//A balance node, just need to adjust the factor. Don't have to recurve since subtree height stays.
			{
				BalanceNode->factor=-PathNode.factor;
				break;
			}
			if (BalanceNode->factor==PathNode.factor) //Node get more balance. Subtree height decrease, need to recurve.
			{
				BalanceNode->factor=0;
				path.pop_back();
				PathNode=path.back();
				continue;
			}
			//Node get out of balance. Here raises 3 cases.
			ChildNode = _FactorLink(BalanceNode, -PathNode.factor);
			if (ChildNode->factor == 0) //New case different to insert operation.
			{
				TryNode = _SingleRotation2( BalanceNode, ChildNode, BalanceNode->factor );
				path.pop_back();
				PathNode=path.back();
				_FactorLink(PathNode.Node, PathNode.factor) = TryNode;
				break;
			}
			else
			{
				if ( ChildNode->factor == BalanceNode->factor ) //Analogous to insert operation case 1.
					TryNode = _SingleRotation( BalanceNode, ChildNode, BalanceNode->factor );
				else if ( ChildNode->factor + BalanceNode->factor == 0 ) //Analogous to insert operation case 2.
					TryNode = _DoubleRotation( BalanceNode, ChildNode, BalanceNode->factor );
			}
			path.pop_back(); //Recurve back along the path.
			PathNode=path.back();
			_FactorLink(PathNode.Node, PathNode.factor) = TryNode;
		}
		return true;
	}

	inline TreeNode<char*,D>* _SingleRotation(TreeNode<char*,D>* BalanceNode, 
		TreeNode<char*,D>* ModifyNode, char factor)
	{
		TreeNode<T*,D>* Node = _FactorLink(ModifyNode, -factor);
		_FactorLink(BalanceNode, factor) = Node;
		_FactorLink(ModifyNode, -factor) = BalanceNode;
		Node->Parent = BalanceNode;
		ModifyNode->Parent = BalanceNode->Parent;
		BalanceNode->Parent = ModifyNode;
		BalanceNode->factor = ModifyNode->factor = 0; //After single rotation, set all factor of 3 node to 0.
		if (factor==1) ModifyNode->rank+=BalanceNode->rank;
		else BalanceNode->rank-=ModifyNode->rank;
		return ModifyNode;
	}
	inline TreeNode<char*,D>* _SingleRotation2(TreeNode<char*,D>* BalanceNode, 
		TreeNode<char*,D>* ModifyNode, char factor)
	{
		TreeNode<T*,D>* Node = _FactorLink(ModifyNode, -factor);
		_FactorLink(BalanceNode, factor) = Node;
		_FactorLink(ModifyNode, -factor) = BalanceNode;
		Node->Parent = BalanceNode;
		ModifyNode->Parent = BalanceNode->Parent;
		BalanceNode->Parent = ModifyNode;
		ModifyNode->factor = -factor;
		return ModifyNode;
	}
	inline TreeNode<char*,D>* _DoubleRotation(TreeNode<char*,D>* BalanceNode, 
		TreeNode<char*,D>* ModifyNode, char factor)
	{
		TreeNode<T*,D>* DownNode = _FactorLink(ModifyNode, -factor);
		TreeNode<T*,D>* Node1, Node2;
		Node1 = _FactorLink(DownNode, factor);
		Node2 = _FactorLink(DownNode, -factor);
		_FactorLink(ModifyNode, -factor) = Node1;
		_FactorLink(DownNode, factor) = ModifyNode;
		_FactorLink(BalanceNode, factor) = Node2;
		_FactorLink(DownNode, -factor) = BalanceNode;
		Node1->Parent = ModifyNode;
		Node2->Parent = BalanceNode;
		DownNode->Parent = BalanceNode->Parent;
		BalanceNode->Parent = DownNode;
		ModifyNode->Parent = DownNode;
		//Set factor according to the result.
		if (DownNode->factor==factor)
		{
			BalanceNode->factor=-factor;
			ModifyNode->factor=0;
		}
		else if (DownNode->factor==0)
		{
			BalanceNode->factor=ModifyNode->factor=0;
		}
		else
		{
			BalanceNode->factor=0;
			ModifyNode->factor=factor;
		}
		DownNode->factor=0;
		if (factor==1) {ModifyNode->rank-=DownNode->rank;DownNode->rank+=BalanceNode->rank;}
		else {DownNode->rank+=ModifyNode->rank;BalanceNode->rank-=DownNode->rank;}
		return DownNode;
	}
	inline TreeNode<char*,D>*&  _FactorLink(TreeNode<char*,D>* Node, char factor)
		//Private helper method to retrieve child according to factor.
		//Return right child if factor>0 and left child otherwise.
	{
		return factor>0? Node->Right : Node->Left;
	}
	void _IncreaseHeight()
	{
		unsigned int k=(unsigned int)head.Right;
		head.Right=(TreeNode<char*,D>*)++k;
	}
	void _DecreaseHeight()
	{
		unsigned int k=(unsigned int)head.Right;
		head.Right=(TreeNode<char*,D>*)--k;
	}
	TreeNode<char*,D> head;
};
